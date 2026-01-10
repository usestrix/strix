import asyncio
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

from litellm import acompletion
from litellm.types.utils import ModelResponseStream

from strix.config import Config


class LLMRequestQueue:
    def __init__(self, max_concurrent: int = 1, delay_between_requests: float = 4.0):
        delay_between_requests = float(Config.get("llm_rate_limit_delay"))  # type: ignore[arg-type]
        max_concurrent = int(Config.get("llm_rate_limit_concurrent"))  # type: ignore[arg-type]

        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    async def stream_request(
        self, completion_args: dict[str, Any]
    ) -> AsyncIterator[ModelResponseStream]:
        try:
            while not self._semaphore.acquire(timeout=0.2):
                await asyncio.sleep(0.1)

            with self._lock:
                now = time.time()
                time_since_last = now - self._last_request_time
                sleep_needed = max(0, self.delay_between_requests - time_since_last)
                self._last_request_time = now + sleep_needed

            if sleep_needed > 0:
                await asyncio.sleep(sleep_needed)

            async for chunk in self._stream_request(completion_args):
                yield chunk
        finally:
            self._semaphore.release()

    async def _stream_request(
        self, completion_args: dict[str, Any]
    ) -> AsyncIterator[ModelResponseStream]:
        response = await acompletion(**completion_args, stream=True)

        async for chunk in response:
            yield chunk


_global_queue: LLMRequestQueue | None = None


def get_global_queue() -> LLMRequestQueue:
    global _global_queue  # noqa: PLW0603
    if _global_queue is None:
        _global_queue = LLMRequestQueue()
    return _global_queue
