# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Value coercion for parameters."""

from typing import Any

from reposcan.cli_kit.spec import Param


def parse_bool(value: str) -> bool:
    """Convert string to boolean, or raise ValueError."""
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"expected a boolean, got {value!r}")


def coerce(param: Param, raw: Any) -> tuple[Any, str | None]:
    """Convert and validate a raw value for `param`, or return (None, message).

    A remainder is taken verbatim. A `many` parameter yields a list.
    """
    if param.remainder:
        return list(raw), None
    if not param.many:
        return _coerce_one(param, raw)
    values: list[Any] = []
    for item in raw if isinstance(raw, list) else [raw]:
        value, error = _coerce_one(param, item)
        if error is not None:
            return None, error
        values.append(value)
    return values, None


def _coerce_one(param: Param, raw: Any) -> tuple[Any, str | None]:
    """Convert and validate a single value for `param`."""
    if param.is_flag:
        if isinstance(raw, bool):
            return raw, None
        return _run(parse_bool, raw, param)
    value: Any = raw
    if param.convert is not None:
        value, error = _run(param.convert, str(raw), param)
        if error is not None:
            return None, error
    if param.choices is not None and value not in param.choices:
        allowed = ", ".join(str(c) for c in param.choices)
        return None, f"invalid value for {param.name}: {value} (choose from {allowed})"
    return value, None


def _run(convert: Any, raw: str, param: Param) -> tuple[Any, str | None]:
    try:
        return convert(raw), None
    except (ValueError, TypeError) as exc:
        return None, f"invalid value for {param.name}: {exc}"
