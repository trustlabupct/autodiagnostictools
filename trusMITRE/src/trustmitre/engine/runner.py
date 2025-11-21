"""Analytic execution runner."""

from __future__ import annotations

import importlib.util
import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from .dsl import AnalyticInterpreter, CompiledAnalytic, Event
from ..report.aggregator import write_detection_artifacts
from ..report.schema import DetectionRecord

logger = logging.getLogger(__name__)


def load_compiled(
    directory: Path,
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> list[CompiledAnalytic]:
    include_set = {item.upper() for item in include or []}
    exclude_set = {item.upper() for item in exclude or []}

    compiled: list[CompiledAnalytic] = []
    for path in sorted(directory.glob("*.py")):
        module_name = f"trustmitre_compiled_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            logger.warning("Unable to load compiled analytic from %s", path)
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "build"):
            logger.debug("%s does not expose build()", path)
            continue
        analytic: CompiledAnalytic = module.build()
        analytic_id = analytic.analytic_id.upper()
        if include_set and analytic_id not in include_set:
            continue
        if exclude_set and analytic_id in exclude_set:
            continue
        compiled.append(analytic)
    return compiled


class Runner:
    def __init__(
        self, analytics: Sequence[CompiledAnalytic], *, workers: int = 1, batch_size: int = 500
    ):
        self.analytics = list(analytics)
        self.workers = max(1, workers)
        self.batch_size = max(1, batch_size)

    def execute(self, events: Iterable[Event]) -> list[DetectionRecord]:
        detections: list[DetectionRecord] = []
        if not self.analytics:
            return detections

        if self.workers > 1:
            try:
                with ProcessPoolExecutor(max_workers=self.workers) as pool:
                    for chunk in _chunked(events, self.batch_size):
                        futures = [
                            pool.submit(_execute_chunk, analytic, chunk)
                            for analytic in self.analytics
                        ]
                        for future in as_completed(futures):
                            detections.extend(future.result())
                return detections
            except (OSError, PermissionError) as exc:
                logger.warning(
                    "Falling back to single-worker execution due to process pool failure: %s",
                    exc,
                )

        interpreters = [AnalyticInterpreter(analytic) for analytic in self.analytics]
        for chunk in _chunked(events, self.batch_size):
            for interpreter in interpreters:
                detections.extend(list(interpreter.execute(chunk)))

        return detections

    def execute_to_artifacts(
        self,
        events: Iterable[Event],
        output_dir: Path,
    ) -> tuple[Path, Path, Path]:
        detections = self.execute(events)
        output_dir.mkdir(parents=True, exist_ok=True)
        return write_detection_artifacts(output_dir, detections)


def _execute_chunk(analytic: CompiledAnalytic, chunk: list[Event]) -> list[DetectionRecord]:
    interpreter = AnalyticInterpreter(analytic)
    return list(interpreter.execute(chunk))


def _chunked(source: Iterable[Event], size: int) -> Iterator[list[Event]]:
    chunk: list[Event] = []
    for item in source:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


__all__ = ["load_compiled", "Runner"]
