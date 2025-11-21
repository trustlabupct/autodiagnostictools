"""Analytic DSL interpreter and helpers."""

from __future__ import annotations

import fnmatch
import operator
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, Mapping, MutableMapping

from trustmitre.report.schema import DetectionRecord

Event = MutableMapping[str, Any]
Dataset = list[Event]


@dataclass(slots=True)
class Operation:
    kind: str
    target: str
    expression: str
    source: str | None = None


@dataclass(slots=True)
class CompiledAnalytic:
    analytic_id: str
    title: str
    description: str | None
    raw_text: str
    operations: list[Operation]

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any]) -> "CompiledAnalytic":
        return cls(
            analytic_id=spec["analytic_id"],
            title=spec.get("title") or spec["analytic_id"],
            description=spec.get("description"),
            raw_text=spec.get("raw_text", ""),
            operations=[Operation(**op) for op in spec.get("operations", [])],
        )


class AnalyticInterpreter:
    """Interpret and execute compiled analytic operations."""

    def __init__(self, analytic: CompiledAnalytic):
        self.analytic = analytic

    def execute(self, events: Iterable[Event]) -> Iterator[DetectionRecord]:
        context: MutableMapping[str, Dataset] = {}
        cache: list[Event] = list(events)

        for op in self.analytic.operations:
            if op.kind == "search":
                context[op.target] = list(_search(cache, op.expression))
            elif op.kind == "filter":
                source = context.get(op.source or op.target, [])
                context[op.target] = list(_filter(source, op.expression))
            elif op.kind == "assign":
                _apply_assignment(context, op)
            elif op.kind == "output":
                targets = _parse_output_targets(op.expression)
                for target in targets:
                    for event in context.get(target, []):
                        yield DetectionRecord.from_event(
                            analytic_id=self.analytic.analytic_id,
                            title=self.analytic.title,
                            event=event,
                        )
            else:
                continue


def _search(events: Iterable[Event], expression: str) -> Iterator[Event]:
    terms = _split_top_level(expression, "OR")
    for event in events:
        event_type = str(event.get("event_type", ""))
        log_type = str(event.get("log_type", ""))
        for term in terms:
            term = term.strip().strip("()")
            if not term:
                continue
            if ":" in term:
                family, action = term.split(":", 1)
                if _match_string(event_type, term):
                    yield event
                    break
                event_action = event_type.split(":", 1)[-1]
                if _match_string(log_type, family) and _match_string(event_action, action):
                    yield event
                    break
            else:
                if _match_string(log_type, term) or _match_string(event_type, term):
                    yield event
                    break


def _filter(dataset: Iterable[Event], expression: str) -> Iterator[Event]:
    for event in dataset:
        if _evaluate_expression(expression, event):
            yield event


def _parse_output_targets(expression: str) -> list[str]:
    text = expression.strip()
    if text.startswith("(") and text.endswith(")"):
        raw = text[1:-1]
        return [item.strip() for item in raw.split(",") if item.strip()]
    return [text]


def _apply_assignment(context: MutableMapping[str, Dataset], op: Operation) -> None:
    if "." not in op.target:
        return
    target_var, field = op.target.split(".", 1)
    dataset = context.get(target_var)
    if not dataset:
        return
    value_expr = op.expression
    for event in dataset:
        existing = event.setdefault("__derived__", {})
        if isinstance(existing, MutableMapping):
            existing[field] = value_expr
        else:
            event["__derived__"] = {field: value_expr}


def _evaluate_expression(expression: str, event: Mapping[str, Any]) -> bool:
    expr = expression.strip()
    if not expr:
        return True

    for part in _split_top_level(expr, "OR"):
        if _evaluate_and_clause(part, event):
            return True
    return False


def _evaluate_and_clause(expression: str, event: Mapping[str, Any]) -> bool:
    tokens = _split_top_level(expression, "AND")
    result = True
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token.upper().startswith("NOT "):
            result = result and not _evaluate_condition(token[4:].strip(), event)
        else:
            result = result and _evaluate_condition(token, event)
        if not result:
            return False
    return result


_SIMPLE_OPERATORS = {
    "=": operator.eq,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}


def _evaluate_condition(clause: str, event: Mapping[str, Any]) -> bool:
    clause = clause.strip()
    if clause.startswith("(") and clause.endswith(")"):
        return _evaluate_expression(clause[1:-1], event)

    if " CONTAINS" in clause.upper():
        field, value = _extract_function_call(clause, "CONTAINS")
        if field is None:
            return False
        field_value = _lookup(event, field)
        pattern = value.strip()
        return _match_contains(field_value, pattern)

    if " STARTSWITH" in clause.upper():
        field, value = _extract_function_call(clause, "STARTSWITH")
        if field is None:
            return False
        field_value = _lookup(event, field)
        return _match_startswith(field_value, value)

    if " ENDSWITH" in clause.upper():
        field, value = _extract_function_call(clause, "ENDSWITH")
        if field is None:
            return False
        field_value = _lookup(event, field)
        return _match_endswith(field_value, value)

    if " IN " in clause.upper():
        field, remainder = clause.split(" IN ", 1)
        field_name = field.strip()
        if not field_name:
            return False
        field_value = _lookup(event, field_name)
        options = [
            item.strip().strip('"\'"')
            for item in remainder.strip("()[]").split(",")
            if item.strip()
        ]
        return any(_match_value(field_value, option) for option in options)

    for op in sorted(_SIMPLE_OPERATORS.keys(), key=len, reverse=True):
        if op in clause:
            left, right = clause.split(op, 1)
            return _compare(_lookup(event, left.strip()), right.strip(), _SIMPLE_OPERATORS[op])

    return False


def _compare(field_value: Any, raw_value: str, comparator: Callable[[Any, Any], bool]) -> bool:
    value = _parse_literal(raw_value)
    if isinstance(value, str) and any(ch in value for ch in "*?["):
        return comparator == operator.eq and _match_wildcard(field_value, value)
    normalized = _normalize(field_value)
    if normalized is None:
        return comparator == operator.ne and value is not None
    try:
        return comparator(normalized, value)
    except TypeError:
        return False


def _parse_literal(raw: str) -> Any:
    text = raw.strip().strip(")").strip("(")
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1]
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def _lookup(container: Mapping[str, Any], dotted_path: str) -> Any:
    value = _lookup_mapping(container, dotted_path)
    if value is not None:
        return value
    attributes = container.get("attributes") if isinstance(container, Mapping) else None
    if isinstance(attributes, Mapping):
        return _lookup_mapping(attributes, dotted_path)
    return None


def _lookup_mapping(mapping: Mapping[str, Any], dotted_path: str) -> Any:
    current: Any = mapping
    for part in dotted_path.strip().split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return value
    if value is None:
        return None
    return str(value)


def _match_contains(value: Any, pattern: str) -> bool:
    normalized = str(value or "")
    candidate = pattern.strip()
    candidate = candidate.strip('"\'"')
    if "*" in candidate or "?" in candidate:
        return fnmatch.fnmatch(normalized.lower(), candidate.lower())
    return candidate.lower() in normalized.lower()


def _match_startswith(value: Any, pattern: str) -> bool:
    candidate = pattern.strip().strip('"\'"')
    return str(value or "").lower().startswith(candidate.lower())


def _match_endswith(value: Any, pattern: str) -> bool:
    candidate = pattern.strip().strip('"\'"')
    return str(value or "").lower().endswith(candidate.lower())


def _match_wildcard(value: Any, pattern: str) -> bool:
    candidate = pattern.strip().strip('"\'"')
    return fnmatch.fnmatch(str(value or ""), candidate)


def _match_value(value: Any, expected: str) -> bool:
    candidate = expected.strip('"\'"')
    return str(value or "").lower() == candidate.lower()


def _match_string(value: str, expected: str) -> bool:
    if value is None:
        return False
    return str(value).lower() == expected.lower()


def _extract_function_call(clause: str, keyword: str) -> tuple[str | None, str]:
    idx = clause.upper().find(keyword)
    field = clause[:idx].strip()
    remainder = clause[idx + len(keyword) :].strip()
    if remainder.startswith("(") and remainder.endswith(")"):
        content = remainder[1:-1]
    else:
        content = remainder
    return field or None, content


def _split_top_level(expression: str, keyword: str) -> list[str]:
    result: list[str] = []
    buffer: list[str] = []
    depth = 0
    i = 0
    keyword_upper = keyword.upper()
    length = len(keyword)
    expr = expression
    while i < len(expr):
        char = expr[i]
        if char == "(":
            depth += 1
            buffer.append(char)
            i += 1
        elif char == ")":
            depth = max(0, depth - 1)
            buffer.append(char)
            i += 1
        elif (
            depth == 0
            and expr[i : i + length].upper() == keyword_upper
            and _is_boundary(expr, i - 1)
            and _is_boundary(expr, i + length)
        ):
            result.append("".join(buffer).strip())
            buffer = []
            i += length
        else:
            buffer.append(char)
            i += 1
    result.append("".join(buffer).strip())
    return [segment for segment in result if segment]


def _is_boundary(text: str, index: int) -> bool:
    if index < 0 or index >= len(text):
        return True
    return not text[index].isalnum()


__all__ = ["CompiledAnalytic", "AnalyticInterpreter"]
