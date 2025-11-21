"""I/O helpers for trustMITRE."""

from __future__ import annotations

import csv
import json
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Any, Dict, Iterable, Iterator, cast

from .paths import ensure_directory

JsonDict = Dict[str, Any]


def read_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, payload: Any, *, indent: int = 2) -> Path:
    target = Path(path)
    ensure_directory(target.parent)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent, sort_keys=True)
        handle.write("\n")
    return target


def iter_json_lines(path: str | Path) -> Iterator[JsonDict]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json_lines(path: str | Path, records: Iterable[JsonDict]) -> Path:
    target = Path(path)
    ensure_directory(target.parent)
    with open(target, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")
    return target


def write_csv(path: str | Path, rows: Iterable[Dict[str, Any]]) -> Path:
    target = Path(path)
    ensure_directory(target.parent)
    iterator = iter(rows)
    try:
        first = next(iterator)
    except StopIteration:
        # create empty file with no rows
        target.touch()
        return target

    fieldnames = list(first.keys())
    with open(target, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(first)
        for row in iterator:
            writer.writerow(row)
    return target


@contextmanager
def atomic_write(path: str | Path, mode: str = "w", encoding: str = "utf-8") -> Iterator[IO[str]]:
    target = Path(path)
    ensure_directory(target.parent)
    with NamedTemporaryFile(delete=False, dir=str(target.parent)) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with open(tmp_path, mode, encoding=encoding) as handle:
            yield cast(IO[str], handle)
        tmp_path.replace(target)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


__all__ = [
    "JsonDict",
    "read_json",
    "write_json",
    "iter_json_lines",
    "write_json_lines",
    "write_csv",
    "atomic_write",
]
