# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Check that every function and method starts with a verb.

A function does something, so its name starts with a verb: `find_violations`, not
`violations_in`; `list_python_files`, not `tracked_python_files`.

The form of the verb decides where a name is allowed:

- infinitives are allowed anywhere.
- dynamic-predicates (third-person forms of dynamic verbs), need `self` as their
  subject and are only allowed on instance methods.
  - okay: `run.matches(other)`
  - not okay: `matches(run, other)`
- stative-predicates are allowed anywhere: `is_sqlite(data)` cannot be misread.
- specific prepositions (`from_` and `to_`) are allowed in certain contexts.
  - `from_` is allowed only on an alternate constructor (a classmethod returning its
    own class)
  - `to_` is allowed on instance conversions (an instance method with no args and
    returning something).

Usage: python tests/lint/verb-check.py [path ...]

Paths are optional; they default to every tracked Python file. They are matched
against ALLOW_LIST as given, so pass them repo-relative to be excused by it.
"""

import ast
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

# A `*` spans directory separators, so `tests/*/conftest.py` covers any depth.
ALLOW_LIST = {
    # cli_kit's parameter DSL: these read as declarations at the point of use
    # e.g., `db: str | None = option(help=...)`
    "src/reposcan/cli_kit/spec.py": {"option", "flag", "positional", "remainder"},
    "*": {
        "main",  # the entry point, by convention.
        "git",  # _git() reads better than _invoke_git
    },
    # pytest looks this hook up by name.
    "tests/*/conftest.py": {"pytest_addoption"},
    # test fakes
    "tests/*": {"json", "isatty"},
    # mirrors stdlib (datetime.now, time.monotonic):
    "src/reposcan/scans/analysis.py": {"utc_now"},
}


VERBS_FILE = Path(__file__).parent / "verbs.txt"

_SECTIONS = ("actions", "stative-predicates", "dynamic-predicates")

_FROM_RULE = (
    "starts with 'from', which is only for an alternate constructor: a classmethod "
    "returning its own class"
)
_TO_RULE = (
    "starts with 'to', which is only for a conversion: an instance method taking "
    "nothing but self and returning something"
)
_PREDICATE_RULE = (
    "starts with {0!r}, a third-person predicate, which needs `self` as its subject: "
    "use it on an instance method, or name it with a base-form verb"
)
_UNKNOWN_RULE = "starts with {0!r}, not a known verb"


def find_allowed(path: Path) -> set[str]:
    """Collect the names ALLOW_LIST excuses in `path`."""
    allowed: set[str] = set()
    for pattern, names in ALLOW_LIST.items():
        if fnmatch(str(path), pattern):
            allowed |= names
    return allowed


@dataclass(frozen=True)
class Vocabulary:
    """The accepted verbs, split by the form that decides where each is allowed."""

    actions: set[str]  # base form; allowed anywhere
    stative_predicates: set[str]  # third person, no action reading; allowed anywhere
    dynamic_predicates: set[str]  # third person; instance methods only

    def knows(self, word: str) -> bool:
        """Whether `word` appears in any section."""
        return word in self.actions | self.stative_predicates | self.dynamic_predicates


def read_verbs() -> Vocabulary:
    """Read verbs.txt into its sections."""
    sections: dict[str, set[str]] = {name: set() for name in _SECTIONS}
    current: str | None = None
    for number, raw in enumerate(VERBS_FILE.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current not in sections:
                raise SystemExit(f"{VERBS_FILE}:{number}: unknown section {line}")
            continue
        if current is None:
            raise SystemExit(f"{VERBS_FILE}:{number}: {line!r} is not under a section")
        sections[current].add(line)
    return Vocabulary(
        actions=sections["actions"],
        stative_predicates=sections["stative-predicates"],
        dynamic_predicates=sections["dynamic-predicates"],
    )


def list_python_files() -> list[Path]:
    """List every Python file git tracks."""
    listed = subprocess.run(
        ["git", "ls-files", "*.py"], capture_output=True, text=True, check=True
    )
    return [Path(name) for name in listed.stdout.split()]


def is_value_or_block(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether the definition is a value or a block rather than an action.

    Properties and setters are attributes; context managers are entered. Both read
    correctly as nouns, so neither is held to the verb rule.
    """
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in {
            "property",
            "cached_property",
            "contextmanager",
            "asynccontextmanager",
        }:
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr in {
            "setter",
            "getter",
            "deleter",
        }:
            return True
    return False


Definition = tuple["ast.FunctionDef | ast.AsyncFunctionDef", "ast.ClassDef | None"]


def find_definitions(tree: ast.Module) -> list[Definition]:
    """Collect the module-level and class-level definitions in `tree`.

    Each is paired with the class that owns it, or None at module level.
    """
    found: list[Definition] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found.append((node, None))
        elif isinstance(node, ast.ClassDef):
            found.extend(
                (child, node)
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            )
    return found


def collect_annotation_names(annotation: ast.AST) -> set[str]:
    """Collect every type name an annotation mentions, quoted or not."""
    names: set[str] = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:  # a quoted forward reference, e.g. -> "SarifRun"
                parsed = ast.parse(node.value, mode="eval").body
            except SyntaxError:
                continue
            if not isinstance(parsed, ast.Constant):
                names |= collect_annotation_names(parsed)
    return names


def has_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    """Whether the definition carries any of the named bare decorators."""
    return any(
        isinstance(decorator, ast.Name) and decorator.id in names
        for decorator in node.decorator_list
    )


def is_alternate_constructor(
    node: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None
) -> bool:
    """Whether the definition is an alternate constructor: `Foo.from_<source>(...)`.

    That means a classmethod on `owner` whose return annotation names `owner` (or
    `Self`), so `from_` reads as "build a Foo from ...". A union such as
    `Repository | None` counts.
    """
    if owner is None or not has_decorator(node, "classmethod"):
        return False
    if node.returns is None:
        return False
    return bool(collect_annotation_names(node.returns) & {owner.name, "Self"})


def is_instance_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None
) -> bool:
    """Whether the definition is an instance method, so `self` supplies the subject."""
    if owner is None or has_decorator(node, "classmethod", "staticmethod"):
        return False
    return bool(node.args.args) and node.args.args[0].arg == "self"


def is_conversion(
    node: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None
) -> bool:
    """Whether the definition is a conversion: `foo.to_<form>()`.

    That means an instance method on `owner` taking nothing but `self` and returning
    something, so `to_` reads as "this object, as a ...".
    """
    if owner is None or has_decorator(node, "classmethod", "staticmethod"):
        return False
    if node.returns is None:
        return False
    if isinstance(node.returns, ast.Constant) and node.returns.value is None:
        return False  # -> None converts nothing
    args = node.args
    takes_only_self = [arg.arg for arg in args.args] == ["self"]
    extras = args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
    return takes_only_self and not extras


def find_violations(path: Path, verbs: Vocabulary) -> list[tuple[int, str, str]]:
    """Find every function in `path` whose name is not a verb phrase.

    Returns:
        The line, name, and why each is wrong, sorted by line.
    """
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except (OSError, SyntaxError) as error:
        return [(0, path.name, f"could not be parsed: {error}")]

    found: list[tuple[int, str, str]] = []
    for node, owner in find_definitions(tree):
        if node.name.startswith("__"):  # dunders are named by the language
            continue
        if is_value_or_block(node):
            continue
        first = node.name.lstrip("_").split("_")[0]
        reason = ""
        if first == "from":
            if not is_alternate_constructor(node, owner):
                reason = _FROM_RULE
        elif first == "to":
            if not is_conversion(node, owner):
                reason = _TO_RULE
        elif first in verbs.dynamic_predicates:
            if not is_instance_method(node, owner):
                reason = _PREDICATE_RULE.format(first)
        elif not verbs.knows(first):
            reason = _UNKNOWN_RULE.format(first)
        if reason:
            found.append((node.lineno, node.name, reason))
    return sorted(found)


# A sample to test every rule
_SAMPLE = """
class Rule:
    def matches(self, other: str) -> bool: ...        # ok: self is the subject
    def is_valid(self) -> bool: ...                   # ok: stative, anywhere
    def to_dict(self) -> dict: ...                    # ok: conversion
    def to_table(self, limit: int) -> dict: ...       # BAD: to_ takes only self

    @classmethod
    def from_dict(cls, d: dict) -> "Rule": ...        # ok: builds its own class
    @classmethod
    def from_text(cls, raw: str) -> str: ...          # BAD: returns another type
    @classmethod
    def ignores(cls, path: str) -> bool: ...          # BAD: predicate needs self


def build_index(x: int) -> int: ...                   # ok: base form
def is_sqlite(data: bytes) -> bool: ...               # ok: stative free function
def unknown_verb(x: int) -> int: ...                  # BAD: not a known verb
def matches(a: str, b: str) -> bool: ...              # BAD: predicate needs self
def from_module(x: int) -> Rule: ...                  # BAD: not a classmethod
def to_module(x: int) -> dict: ...                    # BAD: not an instance method
"""

_EXPECTED = {
    "to_table",
    "from_text",
    "ignores",
    "unknown_verb",
    "matches",
    "from_module",
    "to_module",
}


def verify_self(verbs: Vocabulary) -> None:
    """Run the rules over a known-bad sample."""
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "sample.py"
        sample.write_text(_SAMPLE)
        found = {name for _, name, _ in find_violations(sample, verbs)}
    if found != _EXPECTED:
        raise SystemExit(
            f"{Path(__file__).name} failed its self-test:\n"
            f"  missed    {sorted(_EXPECTED - found)}\n"
            f"  spurious  {sorted(found - _EXPECTED)}"
        )


def main(argv: list[str]) -> int:
    """Enforce function-naming conventions."""
    verbs = read_verbs()
    verify_self(verbs)
    paths = [Path(name) for name in argv] or list_python_files()
    reported = 0
    for path in paths:
        if not path.exists():
            continue
        allowed = find_allowed(path)
        for line, name, reason in find_violations(path, verbs):
            if name.lstrip("_") in allowed:
                continue
            print(f"{path}:{line}: {name} {reason}")
            reported += 1
    if reported:
        print(
            f"\n{reported} function name(s) do not meet project conventions. Rename "
            f"them to a verb phrase (or update {VERBS_FILE.name})."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
