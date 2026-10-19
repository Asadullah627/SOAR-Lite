"""In-process event bus used to push live updates to dashboard WebSocket clients.

publish() may be called from any thread (the poller and playbooks run in worker threads).
"""
import logging
import threading

from backend.database.db import utcnow

log = logging.getLogger("soar.events")

_subscribers = []
_lock = threading.Lock()


def subscribe(callback):
    with _lock:
        _subscribers.append(callback)


def unsubscribe(callback):
    with _lock:
        if callback in _subscribers:
            _subscribers.remove(callback)


def publish(event_type, data=None):
    event = {"type": event_type, "data": data or {}, "timestamp": utcnow()}
    with _lock:
        callbacks = list(_subscribers)
    for callback in callbacks:
        try:
            callback(event)
        except Exception:  # a broken client must never stop the pipeline
            log.exception("event subscriber failed")
