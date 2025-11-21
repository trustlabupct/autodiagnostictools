"""Load CAR analytics from text files into structured metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass(slots=True)
class AnalyticOperation:
    """A parsed CAR operation (search, filter, output, assignment)."""

    kind: str
    target: str
    expression: str
    source: str | None = None


@dataclass(slots=True)
class Analytic:
    """Structured representation of a CAR analytic."""

    analytic_id: str
    title: str
    description: str | None
    raw_text: str
    operations: List[AnalyticOperation]


_OPERATION_PATTERN = re.compile(r"^(?P<lhs>[\w\.]+)\s*=\s*(?P<rhs>.+)$", re.IGNORECASE)
_SEARCH_PATTERN = re.compile(r"^search\s+(?P<source>.+)$", re.IGNORECASE)
_FILTER_PATTERN = re.compile(
    r"^filter\s+(?P<source>[\w\.]+)\s+where\s+(?P<expr>.+)$", re.IGNORECASE
)
_OUTPUT_PATTERN = re.compile(r"^output\s+(?P<expr>.+)$", re.IGNORECASE)
_ASSIGN_PATTERN = re.compile(r"^(?P<target>[\w\.]+)\s*=\s*(?P<expr>.+)$", re.IGNORECASE)


def _normalize_statements(raw_text: str) -> List[str]:
    statements: List[str] = []
    buffer: list[str] = []
    depth = 0
    for raw_line in raw_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        buffer.append(stripped)
        depth += stripped.count("(") - stripped.count(")")
        if depth <= 0:
            statements.append(" ".join(buffer))
            buffer = []
            depth = 0
    if buffer:
        statements.append(" ".join(buffer))
    return statements


def _parse_statement(statement: str) -> AnalyticOperation:
    match = _OUTPUT_PATTERN.match(statement)
    if match:
        return AnalyticOperation("output", "output", match.group("expr").strip(), None)

    match = _OPERATION_PATTERN.match(statement)
    if not match:
        return AnalyticOperation("raw", "", statement)

    lhs = match.group("lhs").strip()
    rhs = match.group("rhs").strip()

    search_match = _SEARCH_PATTERN.match(rhs)
    if search_match:
        return AnalyticOperation("search", lhs, search_match.group("source").strip(), None)

    filter_match = _FILTER_PATTERN.match(rhs)
    if filter_match:
        src = filter_match.group("source").strip()
        expr = filter_match.group("expr").strip()
        return AnalyticOperation("filter", lhs, expr, source=src)

    assign_match = _ASSIGN_PATTERN.match(statement)
    if assign_match:
        return AnalyticOperation("assign", lhs, assign_match.group("expr").strip(), None)

    return AnalyticOperation("raw", lhs, rhs, None)


def load_analytic(path: Path) -> Analytic:
    raw_text = path.read_text(encoding="utf-8")
    analytic_id = path.stem
    statements = _normalize_statements(raw_text)
    operations = [_parse_statement(stmt) for stmt in statements]
    return Analytic(
        analytic_id=analytic_id,
        title=analytic_id.replace("_", " "),
        description=None,
        raw_text=raw_text.strip(),
        operations=operations,
    )


def load_analytics(directory: Path) -> List[Analytic]:
    analytics: List[Analytic] = []
    for path in sorted(directory.glob("CAR-*.txt")):
        analytics.append(load_analytic(path))
    return analytics


def iter_analytics(directory: Path) -> Iterable[Analytic]:
    for path in sorted(directory.glob("CAR-*.txt")):
        yield load_analytic(path)


__all__ = ["Analytic", "AnalyticOperation", "load_analytic", "load_analytics", "iter_analytics"]
