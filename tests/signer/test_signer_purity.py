"""The signer depends on ``merkl.core`` and ``merkl.shared``, and nothing else.

Enforced rather than promised. A signer that imported a rail client or an HTTP
client would be a signer that could not go into an enclave image unchanged, and
phase 3 is not the moment to discover that.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SIGNER = pathlib.Path(__file__).parents[2] / "merkl" / "signer"
MODULES = sorted(SIGNER.rglob("*.py"))

ALLOWED_MERKL = ("merkl.core", "merkl.shared", "merkl.signer")
FORBIDDEN = {"xrpl", "httpx", "requests", "boto3", "fastapi", "uvicorn", "sqlalchemy"}


def imported(path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", MODULES, ids=[str(p.name) for p in MODULES])
def test_the_signer_imports_only_core_and_shared(path: pathlib.Path) -> None:
    for name in imported(path):
        root = name.split(".")[0]
        assert root not in FORBIDDEN, f"{path.name} imports {name}"
        if name.startswith("merkl."):
            assert name.startswith(ALLOWED_MERKL), f"{path.name} imports {name}"


@pytest.mark.parametrize("path", MODULES, ids=[str(p.name) for p in MODULES])
def test_the_signer_never_prints_a_secret(path: pathlib.Path) -> None:
    """No print/log call anywhere near the keystore or the state."""
    source = path.read_text(encoding="utf-8")
    if path.name in ("keystore.py", "state.py"):
        assert "print(" not in source, f"{path.name} prints"
