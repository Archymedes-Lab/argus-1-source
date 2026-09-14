"""Durable change digests and finite age-based escalation, replacing STILL spam."""
import json
import time

from jarvis.response import alert, fixit

from .commands import command_for

QUEUE = 'alert_pending_changes'
LAST_DIGEST = 'alert_digest_last_ok'
RETRY_AT = 'alert_delivery_retry_at'
ESCALATIONS = {
    'critical': (3600, 21600, 86400),
    'high': (86400, 259200, 604800),
    'medium': (259200, 604800, 1209600),
}


def _load(store, key):
    try:
        value = json.loads(store.get_meta(key, '{}') or '{}')
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def deliver(store, job, findings, error=""):
    """Called by the scheduler after every job. Sends at most one email.

    Never raises: an alerting path that can crash the monitor is worse than one
    that occasionally misses. The caller still wraps this in its own guard.
    """
    try:
        conf = alert.load_conf()
        if not alert.enabled(conf):
            return
        dispatch(store, conf, job, list(findings or []), error)
    except Exception:
        pass


def dispatch(store, conf, job, findings, error=''):
    now = int(time.time())
    rank = alert.SEV_RANK
    state = _load(store, alert.STATE_META)
    queue = _load(store, QUEUE)
    minimum = rank.get(conf.get('alert_min_severity', 'high'), 1)
    if error:
        findings = list(findings) + [{
            'category':'collectors', 'severity':'high', 'host':'wsl',
            'title':f"collector '{job}' did not complete observation", 'detail':str(error)[-300:],
            'where':'jarvis serve'}]
    present, advisory = {}, set()
    for f in findings:
        key = alert.finding_key(f)
        if f.get('category') in alert.NOPAGE_CATEGORIES and not alert.is_outage(f):
            advisory.add(key)
        elif rank.get(f.get('severity'), 9) <= minimum or alert.is_outage(f):
            # Duplicate findings may disagree: the worst evidence wins.
            if key not in present or rank.get(f.get('severity'),9) < rank.get(present[key].get('severity'),9):
                present[key] = f

    for key, f in present.items():
        sev = f.get('severity','high')
        outage = alert.is_outage(f)
        st = state.get(key)
        first_observation = st is None
        if st is None:
            st = {'first':now, 'count':0, 'last_sent':0, 'sev':sev, 'job':job}
            state[key] = st
        was = st.get('observed_sev', st.get('sev',sev))
        st.update(finding=f, last_seen=now, observed_sev=sev)
        st['outage'] = outage
        old = queue.get(key)
        age = max(0, now - int(st.get('first',now)))
        thresholds = (900,3600,21600) if outage else ESCALATIONS.get(sev, ESCALATIONS['high'])
        level = sum(age >= t for t in thresholds)
        urgent = outage or sev == 'critical'
        tag = None
        if old and old['tag'] == 'RESOLVED':
            tag = 'REOPENED'
        elif not st.get('last_sent') and (urgent or not first_observation or f.get('remediation')):
            tag = 'NEW'
        elif rank.get(sev,9) < rank.get(was,9):
            tag = 'WORSENED'
        elif st.get('last_sent') and level > int(st.get('escalation',0)):
            tag = 'ESCALATED'
        if old and old['tag'] != 'RESOLVED':
            # Retain an unsent worsening even if no further severity change
            # occurs; severity improvements before send must remain truthful.
            old.update(finding=f, urgent=urgent, level=level)
        elif tag:
            queue[key] = {'tag':tag, 'finding':f, 'job':job, 'queued':now,
                          'urgent':urgent, 'level':level, 'first':st['first']}

    for key in list(state):
        st = state[key]
        if error or key in present or not alert.same_domain(st.get('job',''),job):
            continue
        queue.pop(key, None)
        if st.get('last_sent'):
            # Ledger resolution is a collector fact, independent of mail.
            store.ledger_cleared(key, now)
            if key not in advisory and conf.get('alert_on_clear',False) is True:
                f = st.get('finding') or {
                    'category':key.split('|')[0], 'title':key.split('|')[1],
                    'where':key.split('|',2)[-1], 'severity':st.get('sev','high')}
                queue[key] = {'tag':'RESOLVED', 'finding':f, 'job':job,
                              'queued':now, 'urgent':bool(st.get('outage')),
                              'first':st.get('first',now), 'level':0}
        state.pop(key)
    store.set_meta(alert.STATE_META, json.dumps(state))
    store.set_meta(QUEUE, json.dumps(queue))
    return flush(store, conf)


def flush(store, conf):
    now = int(time.time())
    queue = _load(store, QUEUE)
    if conf.get('alert_on_clear', False) is not True:
        queue = {k: v for k, v in queue.items() if v.get('tag') != 'RESOLVED'}
        store.set_meta(QUEUE, json.dumps(queue))
    if not queue or now < int(store.get_meta(RETRY_AT,0) or 0):
        return False
    period = max(60, alert.parse_int(conf.get('alert_digest_interval'),3600))
    last = int(store.get_meta(LAST_DIGEST,0) or 0)
    oldest = min(item['queued'] for item in queue.values())
    due = now - (last or oldest) >= period
    batch = {k:v for k,v in queue.items() if v.get('urgent') or due}
    if not batch:
        return False
    urgent = any(v.get('urgent') for v in batch.values())
    cap = alert.OUTAGE_HOURLY_CAP if urgent else max(0,alert.parse_int(conf.get('alert_hourly_cap'),12))
    if cap and len(alert.recent_sends(store)) >= cap:
        store.set_meta('alert_capped_at',now)
        return False  # Nothing is acknowledged or discarded.
    ordered = sorted(batch.items(), key=lambda kv: alert.SEV_RANK.get(kv[1]['finding'].get('severity'),9))
    lines = ['JARVIS CHANGE DIGEST' if not urgent else 'JARVIS PRIORITY CHANGES', '']
    for key, item in ordered:
        f = item['finding']
        if item['tag'] == 'RESOLVED':
            lines += [f"NO LONGER OBSERVED: {f.get('title','')}",
                      '  Absent from the latest collector result; this alone does not prove remediation.', '']
            continue
        lines += [f"[{f.get('severity','high').upper()}] {item['tag']}: {f.get('title','')}",
                  f"  {f.get('detail','')}", f"  Where: {f.get('where','') or '—'}; collector: {item['job']}"]
        if item['tag'] == 'ESCALATED':
            lines.append(f"  Unresolved for {(now-item['first'])//3600} hours; escalation {item['level']}.")
        cmd = command_for(item['job'])
        response = f.get('remediation', {})
        lines.append('  Response: ' + response.get('reason',
                     'No safe automatic repair is defined for this finding; investigation or a manual decision is needed.'))
        if cmd: lines.append(f'  Inspect: {cmd}')
        lines.append('')
    lines.append('Unchanged findings stay on the dashboard and in the daily advisory; they do not generate STILL emails.')
    subject = f"[JARVIS] {'priority changes' if urgent else 'change digest'}: {len(batch)} update(s)"
    err = alert.send_email(conf, subject, '\n'.join(lines))
    if err:
        store.set_meta('alert_last_error',f'{now}: {err}'[:300])
        store.set_meta(RETRY_AT,now + 300)
        return False
    state = _load(store,alert.STATE_META)
    for key, item in ordered:
        if item['tag'] != 'RESOLVED':
            st = state.get(key)
            if st:
                st.update(last_sent=now, count=int(st.get('count',0))+1,
                          sev=item['finding'].get('severity','high'), escalation=item['level'])
                st.pop('pending',None)
            store.ledger_sent(key,item['finding'],item['job'],fixit.suggest(item['finding']) or '',now)
        queue.pop(key,None)
    store.set_meta(alert.STATE_META,json.dumps(state))
    store.set_meta(QUEUE,json.dumps(queue))
    alert.record_send(store)
    if due: store.set_meta(LAST_DIGEST,now)
    store.set_meta(RETRY_AT,0)
    store.set_meta('alert_last_ok',now)
    store.set_meta('alert_last_error','')
    return True
