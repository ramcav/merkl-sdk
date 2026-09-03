"""Tests for the base exception hierarchy."""

from __future__ import annotations

from merkl.shared.errors import (
    AnchorError,
    DomainError,
    EntityNotFoundError,
    InfrastructureError,
    RepositoryError,
    TransportError,
    ValidationError,
    MerklError,
)


class TestMerklErrorHierarchy:
    """Verify the exception class hierarchy is correct."""

    def test_merkl_error_is_base_exception(self) -> None:
        err = MerklError("base error")
        assert isinstance(err, Exception)
        assert str(err) == "base error"

    def test_domain_error_hierarchy(self) -> None:
        domain = DomainError("domain")
        validation = ValidationError("bad input")
        not_found = EntityNotFoundError("missing")

        assert isinstance(domain, MerklError)
        assert isinstance(validation, MerklError)
        assert isinstance(validation, DomainError)
        assert isinstance(not_found, MerklError)
        assert isinstance(not_found, DomainError)

    def test_infrastructure_error_hierarchy(self) -> None:
        infra = InfrastructureError("infra")
        repo = RepositoryError("db failed")
        transport = TransportError("network")
        anchor = AnchorError("chain")

        assert isinstance(infra, MerklError)
        assert isinstance(repo, MerklError)
        assert isinstance(repo, InfrastructureError)
        assert isinstance(transport, InfrastructureError)
        assert isinstance(anchor, InfrastructureError)

    def test_error_messages_are_preserved(self) -> None:
        errors = [
            MerklError("msg1"),
            DomainError("msg2"),
            ValidationError("msg3"),
            EntityNotFoundError("msg4"),
            InfrastructureError("msg5"),
            RepositoryError("msg6"),
            TransportError("msg7"),
            AnchorError("msg8"),
        ]
        for i, err in enumerate(errors, start=1):
            assert str(err) == f"msg{i}"
            assert err.message == f"msg{i}"
