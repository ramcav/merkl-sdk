# ADR-001: UUID v7 Library Choice

## Status
Accepted

## Context
The Merkl requires UUID v7 identifiers for SessionId and ActionId value objects (time-sortable, globally unique). Python 3.11 does not include native UUID v7 support — this was added in Python 3.14. We need a library to bridge this gap.

Options considered:
1. `uuid6` — pure Python, well-maintained, returns standard `uuid.UUID` objects
2. `uuid_utils` — Rust-powered via C extension, faster but introduces binary dependency
3. Hand-rolled implementation — maximum control but unnecessary complexity

## Decision
Use the `uuid6` library (version >=2025.0.1).

## Consequences
- Pure Python dependency aligns with the shared kernel's "zero infrastructure" principle
- Returns standard `uuid.UUID` objects, so downstream code is not coupled to the library
- When we upgrade to Python 3.14+, we can drop `uuid6` and use `uuid.uuid7()` directly with no API changes
- Slight performance overhead vs `uuid_utils`, but irrelevant for our use case (ID generation is not a hot path)
