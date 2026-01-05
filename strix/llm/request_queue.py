import asyncio
import logging
import os
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

import litellm
from litellm import completion
from litellm.types.utils import ModelResponseStream
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


logger = logging.getLogger(__name__)


def should_retry_exception(exception: Exception) -> bool:
    status_code = None

    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    elif hasattr(exception, "response") and hasattr(exception.response, "status_code"):
        status_code = exception.response.status_code

    if status_code is not None:
        return bool(litellm._should_retry(status_code))
    return True


class LLMRequestQueue:
    def __init__(self, max_concurrent: int = 1, delay_between_requests: float = 4.0):
        rate_limit_delay = os.getenv("LLM_RATE_LIMIT_DELAY")
        if rate_limit_delay:
            delay_between_requests = float(rate_limit_delay)

        rate_limit_concurrent = os.getenv("LLM_RATE_LIMIT_CONCURRENT")
        if rate_limit_concurrent:
            max_concurrent = int(rate_limit_concurrent)

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

            async for chunk in self._reliable_stream_request(completion_args):
                yield chunk
        finally:
            self._semaphore.release()

    @retry(  # type: ignore[misc]
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=8, min=8, max=64),
        retry=retry_if_exception(should_retry_exception),
        reraise=True,
    )
    async def _reliable_stream_request(
        self, completion_args: dict[str, Any]
    ) -> AsyncIterator[ModelResponseStream]:
        response = await asyncio.to_thread(completion, **completion_args, stream=True)
        for chunk in response:
            yield chunk


_global_queue: LLMRequestQueue | None = None


def get_global_queue() -> LLMRequestQueue:
    global _global_queue  # noqa: PLW0603
    if _global_queue is None:
        _global_queue = LLMRequestQueue()
    return _global_queue
