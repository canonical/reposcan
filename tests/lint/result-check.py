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


def find_weak_narrowings(tree: ast.Module) -> list[tuple[int, str]]:
    """Find every `isinstance(x, Err)` that does not need both branches narrowed.

    `isinstance` is the only form that narrows the success branch as well as the
    failure one, so it is right when both halves are required. Otherwise, prefer:

    - the value unused -> `is_err(x)`, which narrows the failure branch alone
    - the error unused -> `get_value(x)`, which drops the error and yields `T | None`

    A `not isinstance(...)` guard is examined too, with the branches swapped: what the
    body proves is the value, and everything else proves the error. So is a subject
    that is not a plain name, which cannot use a value it never bound.
    """
    found: list[tuple[int, str]] = []
    for owner in ast.walk(tree):
        if not isinstance(owner, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for statement in ast.walk(owner):
            test = getattr(statement, "test", None)
            body = getattr(statement, "body", None)
            if test is None or body is None:
                continue
            statements = body if isinstance(body, list) else [body]
            proven = {node for one in statements for node in ast.walk(one)}
            for call in ast.walk(test):
                if not isinstance(call, ast.Call):
                    continue
                subject = find_err_subject(call)
                if subject is None:
                    continue
                shown = ast.unparse(subject)
                uses_value, uses_error = classify_uses(
                    owner, subject, proven, negated=is_negated(test, call)
                )
                if not uses_value:
                    found.append(
                        (
                            call.lineno,
                            f"isinstance({shown}, Err) never uses the value; "
                            f"prefer is_err",
                        )
                    )
                elif not uses_error:
                    found.append(
                        (
                            call.lineno,
                            f"isinstance({shown}, Err) never uses the error; "
                            f"prefer get_value(...)",
                        )
                    )
    return found


def find_err_subject(node: object) -> ast.expr | None:
    """Take the `x` of an `isinstance(x, Err)`, or None when that is not the shape."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
        return None
    if node.func.id != "isinstance" or len(node.args) != 2:
        return None
    subject, expected = node.args
    if not (isinstance(expected, ast.Name) and expected.id == "Err"):
        return None
    return subject


def is_negated(test: ast.expr, call: ast.AST) -> bool:
    """Whether `call` sits under a `not`, which swaps what each branch proves."""
    return any(
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and any(inner is call for inner in ast.walk(node.operand))
        for node in ast.walk(test)
    )


def classify_uses(
    owner: ast.AST, subject: ast.expr, proven: set[ast.AST], *, negated: bool
) -> tuple[bool, bool]:
    """Report whether the subject's value and its error are each used.

    A subject that is not a plain name bound nothing, so neither half can be used.
    Otherwise only the reads belonging to this binding count: a name reassigned further
    down is a different value, and reads after that point say nothing about this one.

    Returns:
        (uses_value, uses_error).
    """
    if not isinstance(subject, ast.Name):
        return (False, False)
    uses_value = uses_error = False
    for read in find_binding_reads(owner, subject):
        proves_error = (read in proven) != negated
        if proves_error or is_err_read(owner, read):
            uses_error = True
        else:
            uses_value = True
    return (uses_value, uses_error)


def find_binding_reads(owner: ast.AST, subject: ast.Name) -> list[ast.Name]:
    """Every read of `subject` belonging to the binding it was tested under.

    Bounded by the assignments either side of it, so a name reused for a second call
    does not lend its reads to the first.
    """
    named = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Name) and node.id == subject.id
    ]
    stores = sorted(node.lineno for node in named if isinstance(node.ctx, ast.Store))
    opens = max((line for line in stores if line <= subject.lineno), default=0)
    closes = min((line for line in stores if line > subject.lineno), default=10**9)
    return [
        node
        for node in named
        if isinstance(node.ctx, ast.Load)
        and node is not subject
        and opens <= node.lineno < closes
    ]


def is_err_read(owner: ast.AST, read: ast.Name) -> bool:
    """Whether this read reaches `.msg` or `.timed_out`, which only an Err carries."""
    return any(
        isinstance(node, ast.Attribute)
        and node.value is read
        and node.attr in ("msg", "timed_out")
        for node in ast.walk(owner)
    )


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
    if "src" in path.parts:  # see find_weak_narrowings; tests express intent freely
        found += find_weak_narrowings(tree)
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


def weak(x: int) -> Result[str]:
    done = void(x)
    if isinstance(done, Err):
        return done
    return "ok"


def weak_negated(x: int) -> Result[str]:
    flipped = void(x)
    if not isinstance(flipped, Err):
        return "ok"
    return flipped


def weak_unnamed(x: int) -> Result[str]:
    if isinstance(void(x), Err):
        return Err("gave up")
    return "ok"


def weak_rebound(x: int) -> int:
    twice = spelled(x)
    if isinstance(twice, Err):
        return 1
    twice = spelled(x)
    if isinstance(twice, Err):
        return 2
    return len(twice)
"""

# expected self-test findings
_EXPECTED = {
    "bare",
    "pair",
    "raise:raises",  # an ordinary failure
    "raise:stub",  # NotImplementedError outside a class is not a subclass contract
    "is_err:done",  # the plain form
    "is_err:flipped",  # `not isinstance(...)`, which swaps the branches
    "is_err:void(x)",  # a subject that never bound a name
    "is_err:twice",  # the first of two bindings sharing one name
    "get_value:twice",  # the second, whose value is used but whose error is not
    "get_value:got",  # narrows both, but only ever uses the value
}


def build_key(message: str) -> str:
    """Reduce a finding to the rule and subject it came from, for _EXPECTED.

    Every finding must reduce to its own key: two findings that collapse to one tag
    make an extra or a missing one invisible to the set comparison.
    """
    if message.startswith("raise in "):
        return "raise:" + message[len("raise in ") : message.index(" routes")]
    if not message.startswith("isinstance("):
        return message.split()[0]
    subject = message[len("isinstance(") : message.index(", Err)")]
    return f"{'get_value' if 'get_value' in message else 'is_err'}:{subject}"


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
