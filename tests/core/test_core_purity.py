"""``merkl.core`` stays pure — enforced, not just promised.

No HTTP, no database, no filesystem, no clock, no randomness, and no import from
``merkl.sdk`` or ``merkl_api``. The one exception is the vectors *generator*,
which writes fixture files when run as a script.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CORE = pathlib.Path(__file__).parents[2] / "merkl" / "core"
LIBRARY_MODULES = sorted(p for p in CORE.rglob("*.py") if p.name != "generate.py")
ALL_MODULES = sorted(CORE.rglob("*.py"))

FORBIDDEN_IMPORTS = {
    "merkl.sdk",
    "merkl.cli",
    "merkl.hooks",
    "merkl.integrations",
    "merkl_api",
    "httpx",
    "requests",
    "aiohttp",
    "sqlalchemy",
    "asyncpg",
    "psycopg",
    "supabase",
    "os",
    "socket",
    "subprocess",
    "threading",
    "time",
}
IMPURE_CALLS = {"open", "input", "print"}
IMPURE_ATTRIBUTES = {"now", "today", "utcnow", "monotonic", "time_ns"}


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def ids(paths: list[pathlib.Path]) -> list[str]:
    return [str(p.relative_to(CORE)) for p in paths]


@pytest.mark.parametrize("path", ALL_MODULES, ids=ids(ALL_MODULES))
def test_no_forbidden_imports(path: pathlib.Path) -> None:
    for name in imported_modules(path):
        root = name.split(".")[0]
        assert name not in FORBIDDEN_IMPORTS, f"{path.name} imports {name}"
        assert root not in FORBIDDEN_IMPORTS or name.startswith("merkl.core"), (
            f"{path.name} imports {name}"
        )


@pytest.mark.parametrize("path", ALL_MODULES, ids=ids(ALL_MODULES))
def test_only_stdlib_and_merkl_shared(path: pathlib.Path) -> None:
    for name in imported_modules(path):
        if name.startswith("merkl."):
            assert name.startswith(("merkl.core", "merkl.shared")), f"{path.name} imports {name}"


@pytest.mark.parametrize("path", LIBRARY_MODULES, ids=ids(LIBRARY_MODULES))
def test_library_modules_do_no_io_and_read_no_clock(path: pathlib.Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                assert func.id not in IMPURE_CALLS, f"{path.name} calls {func.id}()"
            if isinstance(func, ast.Attribute):
                assert func.attr not in IMPURE_ATTRIBUTES, f"{path.name} calls .{func.attr}()"


def test_only_the_generators_write() -> None:
    """Four of them: the receipt vectors, the attestation ones, the bundles, and xrpl.

    All are scripts rather than library code — they are excluded from
    ``LIBRARY_MODULES`` above and run by hand or by CI, never on an import path.
    Anything else in ``merkl.core`` that touched a file would be a verifier that
    needs a filesystem to answer a question about bytes it was handed.
    """
    writers = {
        str(p.relative_to(CORE))
        for p in ALL_MODULES
        if "write_text" in p.read_text(encoding="utf-8")
        or "open(" in p.read_text(encoding="utf-8")
    }
    assert writers == {
        "vectors/generate.py",
        "vectors/attestation/generate.py",
        "vectors/bundles/generate.py",
        "vectors/xrpl/generate.py",
    }
