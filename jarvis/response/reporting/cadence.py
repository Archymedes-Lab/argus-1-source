"""Daily advisory eligibility; change digests are driven by collector results."""
import time

from jarvis.response import alert

from . import advisory, emails, notifications, score


def daily_due(store, conf, now=None):
    now = int(time.time() if now is None else now)
    hour = min(23,max(0,alert.parse_int(conf.get('report_hour'),9)))
    last = int(store.get_meta('report_daily_last_ok',0) or
               store.get_meta(alert.REPORT_OK_META,0) or 0)
    current = time.localtime(now)
    if current.tm_hour < hour:
        return False
    return not last or time.strftime('%Y-%m-%d',time.localtime(last)) != time.strftime('%Y-%m-%d',current)


def health_due(store, conf, now=None):
    """Once a day at report_hour, like the advisory, on its own bookmark."""
    now = int(time.time() if now is None else now)
    hour = min(23,max(0,alert.parse_int(conf.get('report_hour'),9)))
    last = int(store.get_meta('health_email_last_ok',0) or 0)
    current = time.localtime(now)
    if current.tm_hour < hour:
        return False
    return not last or time.strftime('%Y-%m-%d',time.localtime(last)) != time.strftime('%Y-%m-%d',current)


def run(store, jobs):
    # Recorded on every pass, email or not: the dashboard trend and the digest
    # header both read this history.
    score.record(store, jobs)
    conf = alert.load_conf()
    if not alert.enabled(conf):
        return advisory.advisory_report(store,jobs)
    notifications.flush(store,conf)
    if conf.get('report_daily_enabled', False) is not True:
        # The full advisory is off, but the health bar still arrives once a
        # day unless health_email_enabled is set to false.
        now = int(time.time())
        if (conf.get('health_email_enabled', True) is not False and health_due(store, conf, now)
                and now >= int(store.get_meta('health_email_retry_at',0) or 0)):
            err = emails.health_email(store, conf, now, jobs)
            if err:
                store.set_meta('health_email_retry_at', now + 900)
                store.set_meta('alert_last_error', f'{now}: {err}'[:300])
            else:
                store.set_meta('health_email_last_ok', now)
                store.set_meta('health_email_retry_at', 0)
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'automatic repairs and attention alerts active',
                 'detail':'Routine daily email is disabled; findings remain on the dashboard.',
                 'where':'scheduler'}]
    now = int(time.time())
    if now < int(store.get_meta('report_retry_at',0) or 0) or not daily_due(store,conf,now):
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'daily advisory scheduled; change digests active',
                 'detail':'Unchanged findings do not send repeat alerts.','where':'scheduler'}]
    result = advisory.advisory_report(store,jobs)
    if int(store.get_meta(alert.REPORT_OK_META,0) or 0) >= now:
        store.set_meta('report_daily_last_ok',now)
        store.set_meta('report_retry_at',0)
    else:
        store.set_meta('report_retry_at',now+900)
    return result
