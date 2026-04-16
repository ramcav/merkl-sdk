"""Base domain and infrastructure exceptions for Merkl."""

from __future__ import annotations


class MerklError(Exception):
    """Base exception for all Merkl errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class DomainError(MerklError):
    """Base exception for domain-level errors."""


class ValidationError(DomainError):
    """Raised when a value object or entity fails validation.

    Subclasses may override `error_code` with a stable machine-readable
    identifier so clients (SDK, dashboard) can branch on the cause
    without regex-matching the human-readable message.
    """

    error_code: str = "validation_error"


class EntityNotFoundError(DomainError):
    """Raised when an expected entity does not exist."""


class InfrastructureError(MerklError):
    """Base exception for infrastructure-level errors."""


class RepositoryError(InfrastructureError):
    """Raised when a repository operation fails."""


class TransportError(InfrastructureError):
    """Raised when a transport/network operation fails."""


class AnchorError(InfrastructureError):
    """Raised when an on-chain anchoring operation fails."""
