# ADR-003: Hatchling Build Backend

## Status
Accepted

## Context
The merkl-sdk package needs a PEP 517/518 compliant build backend. Options: hatchling, setuptools, flit, poetry-core.

## Decision
Use hatchling as the build backend.

## Consequences
- PEP 517/518 compliant — works with `uv`, `pip`, `poetry`, and any modern installer
- No `setup.py` or `setup.cfg` needed — everything in `pyproject.toml`
- Does not force a specific workflow tool on consumers
- Well-maintained by the PyPA community
- Supports editable installs out of the box
