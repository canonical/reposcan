# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The return type used for all fallible functions.

A fallible call returns `Result[T]`, which is `T | Err`, so the caller cannot reach the
value without first ruling out the error:

    reference = ensure_built(builder, spec)
    if isinstance(reference, Err):
        logger.error(reference.msg)
        return 1
    ctx = backend.context(reference)

Use `isinstance(x, Err)` whenever both the value and the error must be type-narrowed.
(`TypeIs` would also narrow both branches, but it needs Python 3.13.)

When the value is not needed, use `is_err`:

    if is_err(e := write_json(document, path)):
        logger.error(e.msg)
        return 1

When the error is not needed, use `get_value`:

    identity = get_value(run_process(argv, check=True))
    # identity is now ExecResult | None

When the value is not needed but the error must be kept, use `get_err`:

    return get_err(_provision_image(backend, image))
    # returns Err | None
"""

from dataclasses import dataclass
from typing import TypeAlias, TypeGuard, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Err:
    """Error-as-data. Contains a message."""

    msg: str
    timed_out: bool = False

    def __bool__(self) -> bool:
        """Return False if cast as a bool."""
        return False


Result: TypeAlias = T | Err


def is_err(result: Result[object]) -> TypeGuard[Err]:
    """Report whether an object is an Err."""
    return isinstance(result, Err)


def get_value(result: Result[T]) -> T | None:
    """Convert Result[T] to T | None."""
    return None if isinstance(result, Err) else result


def get_err(result: Result[object]) -> Result[None]:
    """Convert Result[T] to Err | None."""
    return result if isinstance(result, Err) else None
