import asyncio
import logging
import threading
import time
from typing import Any

import litellm
from litellm import ModelResponse, completion
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
    def __init__(self, max_concurrent: int = 6, delay_between_requests: float = 1.0):
        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    async def make_request(self, completion_args: dict[str, Any]) -> ModelResponse:
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

            return await self._reliable_request(completion_args)
        finally:
            self._semaphore.release()

    @retry(  # type: ignore[misc]
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=1, max=30),
        retry=retry_if_exception(should_retry_exception),
        reraise=True,
    )
    async def _reliable_request(self, completion_args: dict[str, Any]) -> ModelResponse:
        response = completion(**completion_args, stream=False)
        if isinstance(response, ModelResponse):
            return response
        self._raise_unexpected_response()
        raise RuntimeError("Unreachable code")

    def _raise_unexpected_response(self) -> None:
        raise RuntimeError("Unexpected response type")


_global_queue: LLMRequestQueue | None = None


def get_global_queue() -> LLMRequestQueue:
    global _global_queue  # noqa: PLW0603
    if _global_queue is None:
        _global_queue = LLMRequestQueue()
    return _global_queue
