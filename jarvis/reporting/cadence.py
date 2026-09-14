"""Daily advisory eligibility; change digests are driven by collector results."""
import time


def daily_due(store, conf, now=None):
    now = int(time.time() if now is None else now)
    from .. import alert
    hour = min(23,max(0,alert._int(conf.get('report_hour'),9)))
    last = int(store.get_meta('report_daily_last_ok',0) or
               store.get_meta(alert._M_REPORT_OK,0) or 0)
    current = time.localtime(now)
    if current.tm_hour < hour:
        return False
    return not last or time.strftime('%Y-%m-%d',time.localtime(last)) != time.strftime('%Y-%m-%d',current)


def run(store, jobs):
    from .. import alert
    from . import notifications
    conf = alert.load_conf()
    if not alert.enabled(conf):
        return alert.advisory_report(store,jobs)
    notifications.flush(store,conf)
    if conf.get('report_daily_enabled', False) is not True:
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'automatic repairs and attention alerts active',
                 'detail':'Routine daily email is disabled; findings remain on the dashboard.',
                 'where':'scheduler'}]
    now = int(time.time())
    if now < int(store.get_meta('report_retry_at',0) or 0) or not daily_due(store,conf,now):
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'daily advisory scheduled; change digests active',
                 'detail':'Unchanged findings do not send repeat alerts.','where':'scheduler'}]
    result = alert.advisory_report(store,jobs)
    if int(store.get_meta(alert._M_REPORT_OK,0) or 0) >= now:
        store.set_meta('report_daily_last_ok',now)
        store.set_meta('report_retry_at',0)
    else:
        store.set_meta('report_retry_at',now+900)
    return result
