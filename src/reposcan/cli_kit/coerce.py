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
    """Convert and validate a raw value for `param`, or return (None, message)."""
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
