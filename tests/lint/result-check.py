# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Check that fallible functions use the Result return type.

This test checks for three things:

1. a return annotation naming Err, instead of Result[...]
2. a `(value, error)` tuple
3. `raise`, which routes a failure around the Result the caller is checking

The `raise` rule applies to src/ only, and has exceptions:

- `raise NotImplementedError` in a Protocol or base-class stub; in a free function
  the same raise is unimplemented code, not a subclass contract, so it is reported
- class constructors, which cannot return a Result;
- converters listed in RAISING_CONVERTERS that are called by cli_kit; they are caught
  and converted by `cli_kit.coerce._run`

Usage: python tests/lint/result-check.py [path ...]
"""

import ast
import subprocess
import sys
import tempfile
from pathlib import Path

EXEMPT = {"src/reposcan/result.py"}

# cli_kit calls these through a `convert=` parameter, whose protocol is to raise on a
# bad value; coerce._run catches and returns the Result.
RAISING_CONVERTERS = {
    "src/reposcan/cli_kit/coerce.py",
    "src/reposcan/actions/base.py",
    "src/reposcan/scans/registry.py",
}


def list_python_files() -> list[Path]:
    """List every Python file git tracks."""
    listed = subprocess.run(
        ["git", "ls-files", "*.py"], capture_output=True, text=True, check=True
    )
    return [Path(name) for name in listed.stdout.split()]


def is_bare_failure(annotation: ast.AST) -> bool:
    """Whether a return annotation hands back an Err rather than a Result.

    `Result[str]` is the shape being asked for and names no Err, so it is not a
    finding; `str | Err` and a plain `Err` are. Recurses because the Err can be nested
    in a union, a subscript, or a quoted forward reference.
    """
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        try:  # a quoted forward reference, e.g. -> "str | Err"
            return is_bare_failure(ast.parse(annotation.value, mode="eval").body)
        except SyntaxError:
            return False
    if isinstance(annotation, ast.Name):
        return annotation.id == "Err"
    return any(is_bare_failure(child) for child in ast.iter_child_nodes(annotation))


def is_optional(node: ast.AST) -> bool:
    """Whether the annotation is `X | None`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return is_optional(ast.parse(node.value, mode="eval").body)
        except SyntaxError:
            return False
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.BitOr)
        and any(
            isinstance(side, ast.Constant) and side.value is None
            for side in (node.left, node.right)
        )
    )


def is_value_error_pair(node: ast.AST) -> bool:
    """Whether the annotation is a `(value, error)` tuple standing in for a Result.

    A two-tuple whose second element is optional is the Go pair by hand: the caller
    unpacks both and nothing makes it look at the error.
    """
    if not isinstance(node, ast.Subscript):
        return False
    target = node.value
    if not (isinstance(target, ast.Name) and target.id == "tuple"):
        return False
    elements = node.slice.elts if isinstance(node.slice, ast.Tuple) else []
    return len(elements) == 2 and is_optional(elements[1])


CONSTRUCTORS = {"__init__", "__post_init__", "__new__"}


def find_owner(tree: ast.Module, node: ast.Raise) -> str:
    """Name the definition a `raise` sits in, as `Class.method` for a method.

    The class half is what tells a subclass contract from ordinary unimplemented code,
    so the two exemptions below need it, not just the function name.
    """
    for klass in ast.walk(tree):
        if not isinstance(klass, ast.ClassDef):
            continue
        for method in klass.body:
            if isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef) and any(
                node is inner for inner in ast.walk(method)
            ):
                return f"{klass.name}.{method.name}"
    for candidate in ast.walk(tree):
        if isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            node is inner for inner in ast.walk(candidate)
        ):
            return candidate.name
    return ""


def is_error_handling(node: ast.Raise, path: str, owner: str) -> bool:
    """Whether a `raise` reports a failure rather than declaring something structural.

    `raise NotImplementedError` declares that a subclass must supply the body; a
    constructor has no return channel to put a Result in; and a converter listed in
    RAISING_CONVERTERS raises by contract. None of those is a failure a caller could
    check for.

    The first two need a class to mean anything. A free function has no subclass, so
    `raise NotImplementedError` there is unimplemented code rather than a contract,
    and a module-level `__init__` constructs nothing. Both are reported.
    """
    if path in RAISING_CONVERTERS:
        return False
    klass, _, name = owner.rpartition(".")
    if klass and name in CONSTRUCTORS:
        return False
    raised = node.exc
    if raised is None:
        return True  # a bare re-raise
    named = raised.func if isinstance(raised, ast.Call) else raised
    stub = isinstance(named, ast.Name) and named.id == "NotImplementedError"
    return not (stub and klass)


def find_isinstance_checks(tree: ast.Module) -> list[tuple[int, str]]:
    """Find every `isinstance(x, Err)`, which `is_err(x)` narrows identically."""
    found: list[tuple[int, str]] = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
            continue
        if call.func.id != "isinstance" or len(call.args) != 2:
            continue
        subject, expected = call.args
        if isinstance(expected, ast.Name) and expected.id == "Err":
            shown = ast.unparse(subject)
            found.append((call.lineno, f"isinstance({shown}, Err); use is_err"))
    return found


def find_violations(path: Path) -> list[tuple[int, str]]:
    """Find every unspelled Result, hand-rolled pair, and raised failure."""
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except (OSError, SyntaxError) as error:
        return [(0, f"could not parse: {error}")]

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.returns is None:
                continue
            if is_bare_failure(node.returns):
                found.append(
                    (
                        node.lineno,
                        f"{node.name} returns a bare Err; return Result[...] instead",
                    )
                )
            elif is_value_error_pair(node.returns):
                found.append(
                    (
                        node.lineno,
                        f"{node.name} returns a (value, error) tuple; "
                        f"return Result[...] instead",
                    )
                )
        elif isinstance(node, ast.Raise):
            # Matched on the path's parts, not a "src/" prefix, so the rule holds for
            # an absolute path and for the sample verify_self() writes to a temp dir.
            if "src" not in path.parts:
                continue
            owner = find_owner(tree, node)
            if not is_error_handling(node, str(path), owner):
                continue
            found.append(
                (
                    node.lineno,
                    f"raise in {owner or 'module scope'} routes a failure past the "
                    f"caller's Result; return an Err instead",
                )
            )
    found += find_isinstance_checks(tree)
    return sorted(found)


# A sample for self-testing. Checked before each run.
_SAMPLE = """
from reposcan.result import Err, Result


def bare(x: int) -> str | Err: ...
def pair(x: int) -> tuple[str, str | None]: ...
def spelled(x: int) -> Result[str]: ...
def void(x: int) -> Result[None]: ...


def stub(x: int) -> Result[str]:
    raise NotImplementedError                   # BAD: a free function has no subclass


class Thing:
    def __init__(self, n: int) -> None:
        raise ValueError("a constructor has no return channel")

    def build(self, n: int) -> Result[str]:
        raise NotImplementedError               # ok: a subclass supplies the body


def raises(x: int) -> Result[str]:
    raise ValueError("nope")


def narrows(x: int) -> int:
    got = spelled(x)
    if isinstance(got, Err):
        return 1
    return len(got)
"""

# expected self-test findings
_EXPECTED = {
    "bare",
    "pair",
    "raise:raises",  # an ordinary failure
    "raise:stub",  # NotImplementedError outside a class is not a subclass contract
    "is_err:got",  # `isinstance(x, Err)`
}


def build_key(message: str) -> str:
    """Reduce a finding to the rule and subject it came from, for _EXPECTED.

    Every finding must reduce to its own key: two findings that collapse to one tag
    make an extra or a missing one invisible to the set comparison.
    """
    if message.startswith("raise in "):
        return "raise:" + message[len("raise in ") : message.index(" routes")]
    if message.startswith("isinstance("):
        return "is_err:" + message[len("isinstance(") : message.index(", Err)")]
    return message.split()[0]


def verify_self() -> None:
    """Run the rules over a known-bad sample."""
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "src" / "reposcan" / "sample.py"
        sample.parent.mkdir(parents=True)
        sample.write_text(_SAMPLE)
        found = {build_key(message) for _, message in find_violations(sample)}
    if found != _EXPECTED:
        raise SystemExit(
            f"{Path(__file__).name} failed its self-test:\n"
            f"  expected {sorted(_EXPECTED)}\n"
            f"  got      {sorted(found)}"
        )


def main(argv: list[str]) -> int:
    """Enforce the Result return type."""
    verify_self()
    paths = [Path(name) for name in argv] or list_python_files()
    reported = 0
    for path in paths:
        if str(path) in EXEMPT or not path.exists():
            continue
        for line, message in find_violations(path):
            print(f"{path}:{line}: {message}")
            reported += 1
    if reported:
        print(f"\n{reported} finding(s); see src/reposcan/result.py.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
