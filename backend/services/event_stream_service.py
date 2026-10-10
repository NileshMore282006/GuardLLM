"""
Real-Time Security Event Stream Service
Broadcasts live security events, attack interceptions, tool approval requests,
and DLP privacy alerts to connected SOC Dashboard operators via Server-Sent Events (SSE).
"""

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, List, Set

logger = logging.getLogger("agentguard.event_stream")


class EventStreamBroadcaster:
    """
    Manages active SSE subscriber queues and dispatches real-time security events.
    """

    def __init__(self, history_buffer_size: int = 50):
        self._subscribers: Set[asyncio.Queue] = set()
        self._history: List[Dict[str, Any]] = []
        self._history_buffer_size = history_buffer_size

    def broadcast(self, event_data: Dict[str, Any]):
        """
        Dispatches an event payload to all currently connected SOC dashboard subscribers.
        Thread-safe and non-blocking.
        """
        if not event_data:
            return

        # Ensure timestamp is populated
        if "timestamp" not in event_data:
            event_data["timestamp"] = time.time()

        # Retain recent events in ring buffer
        self._history.append(event_data)
        if len(self._history) > self._history_buffer_size:
            self._history.pop(0)

        # Broadcast to active queues
        dead_queues = set()
        for q in list(self._subscribers):
            try:
                q.put_nowait(event_data)
            except asyncio.QueueFull:
                logger.warning("Subscriber queue full; dropping event.")
            except Exception:
                dead_queues.add(q)

        self._subscribers.difference_update(dead_queues)

    def get_recent_events(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Returns the most recent events from the in-memory buffer."""
        return self._history[-limit:]

    async def subscribe(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronous generator yielding live events to an SSE connection.
        Cleans up subscriber queue on disconnect.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)

        try:
            while True:
                event = await queue.get()
                yield event
        except asyncio.CancelledError:
            pass
        finally:
            self._subscribers.discard(queue)


# Global singleton broadcaster
event_broadcaster = EventStreamBroadcaster()
