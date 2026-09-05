# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Value coercion for parameters.

A `convert=` hook raises ValueError or TypeError to reject a value; `_run` is the
single boundary that catches that and returns an `Err`.
"""

from typing import Any

from reposcan.cli_kit.spec import Param
from reposcan.result import Err, Result


def parse_bool(value: str) -> bool:
    """Parse `value` as a boolean."""
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"expected a boolean, got {value!r}")


def coerce(param: Param, raw: Any) -> Result[Any]:
    """Convert and validate a raw value for `param`.

    A remainder is taken verbatim. A `many` parameter yields a list.
    """
    if param.remainder:
        return list(raw)
    if not param.many:
        return _coerce_one(param, raw)
    values: list[Any] = []
    for item in raw if isinstance(raw, list) else [raw]:
        coerced = _coerce_one(param, item)
        if isinstance(coerced, Err):
            return coerced
        values.append(coerced)
    return values


def _coerce_one(param: Param, raw: Any) -> Result[Any]:
    """Convert and validate a single value for `param`."""
    if param.is_flag:
        if isinstance(raw, bool):
            return raw
        return _run(parse_bool, raw, param)
    value: Any = raw
    if param.convert is not None:
        value = _run(param.convert, str(raw), param)
        if isinstance(value, Err):
            return value
    if param.choices is not None and value not in param.choices:
        allowed = ", ".join(str(c) for c in param.choices)
        return Err(f"invalid value for {param.name}: {value} (choose from {allowed})")
    return value


def _run(convert: Any, raw: str, param: Param) -> Result[Any]:
    # cli_kit's converter protocol raises; this is the boundary that turns
    # that into a Result, so nothing above it has to catch.
    try:
        return convert(raw)
    except (ValueError, TypeError) as exc:
        return Err(f"invalid value for {param.name}: {exc}")
