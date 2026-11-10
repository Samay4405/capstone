"""Async task queue and background worker for asynchronous email analysis."""

import asyncio
import logging
import uuid
from typing import Dict, Any, Optional
from active_verification.models.schemas import EmailMessage, AnalysisResult
from active_verification.ensemble.engine import ensemble_engine

logger = logging.getLogger(__name__)


class TaskRecord:
    def __init__(self, task_id: str, email: EmailMessage):
        self.task_id = task_id
        self.email = email
        self.status = "PENDING"  # PENDING, PROCESSING, COMPLETED, FAILED
        self.result: Optional[AnalysisResult] = None
        self.error: Optional[str] = None


class AsyncQueueWorker:
    """Manages asynchronous job queue for high-throughput mail streams."""

    def __init__(self, concurrency: int = 4):
        self.concurrency = concurrency
        self._queue: asyncio.Queue = asyncio.Queue()
        self._tasks: Dict[str, TaskRecord] = {}
        self._workers: list = []
        self._running = False

    async def start(self):
        """Start worker coroutines."""
        if self._running:
            return
        self._running = True
        for i in range(self.concurrency):
            w = asyncio.create_task(self._worker_loop(i))
            self._workers.append(w)
        logger.info(f"Started {self.concurrency} async queue workers.")

    async def stop(self):
        """Stop worker coroutines gracefully."""
        self._running = False
        for w in self._workers:
            w.cancel()
        self._workers.clear()

    async def enqueue(self, email: EmailMessage) -> str:
        """Enqueue an email for background analysis and return task_id."""
        task_id = f"task_{uuid.uuid4().hex[:12]}"
        record = TaskRecord(task_id, email)
        self._tasks[task_id] = record
        await self._queue.put(record)
        return task_id

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve current status and result for task_id."""
        record = self._tasks.get(task_id)
        if not record:
            return None
        return {
            "task_id": record.task_id,
            "status": record.status,
            "message_id": record.email.id,
            "error": record.error,
            "result": record.result.model_dump() if record.result else None,
        }

    async def _worker_loop(self, worker_id: int):
        """Background worker consuming messages from the queue."""
        while self._running:
            try:
                record: TaskRecord = await self._queue.get()
                record.status = "PROCESSING"
                try:
                    # Run CPU-bound ensemble analysis in threadpool executor to avoid blocking event loop
                    loop = asyncio.get_running_loop()
                    result = await loop.run_in_executor(
                        None, ensemble_engine.analyze_message, record.email
                    )
                    record.result = result
                    record.status = "COMPLETED"
                except Exception as ex:
                    logger.error(f"Worker {worker_id} failed on task {record.task_id}: {ex}")
                    record.status = "FAILED"
                    record.error = str(ex)
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected worker loop exception: {e}")


async_queue = AsyncQueueWorker()

