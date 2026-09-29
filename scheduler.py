import os
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.base import JobLookupError

scheduler = AsyncIOScheduler()

def get_interval_hours():
    try:
        return int(os.environ.get("SCAN_INTERVAL_HOURS", 6))
    except ValueError:
        return 6

def get_scheduler_status(total_monitored_domains: int = 0):
    running = scheduler.running
    next_run_time = None

    if running:
        try:
            job = scheduler.get_job('periodic_monitor_audit')
            if job and job.next_run_time:
                next_run_time = job.next_run_time.isoformat()
        except JobLookupError:
            pass

    return {
        "scheduler_running": running,
        "next_run_time": next_run_time,
        "interval_hours": get_interval_hours(),
        "total_monitored_domains": total_monitored_domains
    }

def start_scheduler(run_check_func):
    interval_hours = get_interval_hours()

    scheduler.add_job(
        run_check_func,
        'interval',
        hours=interval_hours,
        id='periodic_monitor_audit',
        replace_existing=True
    )

    if not scheduler.running:
        scheduler.start()

def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
