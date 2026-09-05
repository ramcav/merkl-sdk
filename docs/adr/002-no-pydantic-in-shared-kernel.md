# ADR-002: No Pydantic in Shared Kernel

## Status
Accepted

## Context
The spec lists Pydantic as a potential runtime dependency for the SDK. The shared kernel contains value objects used across all bounded contexts. We need to decide whether value objects should be Pydantic models or plain frozen dataclasses.

## Decision
Use plain frozen dataclasses for all shared kernel value objects. Pydantic will be introduced in later bounded contexts (API layer, serialization) where its validation and serialization features are needed.

## Consequences
- The domain layer remains pure Python with minimal dependencies (only `uuid6`)
- Frozen dataclasses provide immutability guarantees without runtime overhead
- `mypy --strict` works seamlessly with frozen dataclasses
- Pydantic models in the API layer can wrap/convert these value objects when needed for serialization
- No coupling between domain model representation and wire format
