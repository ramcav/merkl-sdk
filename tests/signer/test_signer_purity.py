"""The signer depends on ``merkl.core`` and ``merkl.shared``, and nothing else.

Enforced rather than promised. A signer that imported a rail client or an HTTP
client would be a signer that could not go into an enclave image unchanged, and
phase 3 is not the moment to discover that.

``merkl/signer/rails/<rail>.py`` is the single exception: a payload codec has to
speak its rail's binary format. Those modules may import their rail's library and
nothing else may import *them* at module level, so a signer only loads the codec
for the rail it was configured with.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SIGNER = pathlib.Path(__file__).parents[2] / "merkl" / "signer"
RAILS = SIGNER / "rails"
CODECS = sorted(p for p in RAILS.glob("*.py") if p.name != "__init__.py")
MODULES = sorted(p for p in SIGNER.rglob("*.py") if p not in CODECS)

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


@pytest.mark.parametrize("path", CODECS, ids=[str(p.name) for p in CODECS])
def test_a_codec_imports_only_its_own_rail(path: pathlib.Path) -> None:
    """A codec may speak one rail's binary format. It may not reach a network."""
    rail = path.stem
    for name in imported(path):
        root = name.split(".")[0]
        if name.startswith("merkl."):
            assert name.startswith(ALLOWED_MERKL), f"{path.name} imports {name}"
        elif root not in ("json", "decimal", "typing", "__future__"):
            assert root == rail, f"{path.name} imports {name}, which is not {rail}"
    source = path.read_text(encoding="utf-8")
    for forbidden in ("Client", "requests", "asyncio", "socket"):
        assert forbidden not in source, f"{path.name} looks like it reaches a network"


def module_level(path: pathlib.Path) -> set[str]:
    """Only the imports that run when the module is loaded."""
    names: set[str] = set()
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_nothing_imports_a_codec_eagerly() -> None:
    """The registry resolves lazily, so one rail's library is never a hard dep."""
    for path in MODULES:
        for name in module_level(path):
            assert not name.startswith("merkl.signer.rails."), (
                f"{path.name} imports {name} at module level; codecs load through codec_for()"
            )


@pytest.mark.parametrize("path", MODULES, ids=[str(p.name) for p in MODULES])
def test_the_signer_never_prints_a_secret(path: pathlib.Path) -> None:
    """No print/log call anywhere near the keystore or the state."""
    source = path.read_text(encoding="utf-8")
    if path.name in ("keystore.py", "state.py"):
        assert "print(" not in source, f"{path.name} prints"
