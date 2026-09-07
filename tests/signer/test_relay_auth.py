"""Relay bearer tokens — who may call anything on the signer but ``propose``."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from merkl.core.canonical import ContentError
from merkl.signer.relay_auth import (
    RelayAuthError,
    RelayToken,
    RelayTokenStore,
    bearer_from_authorization,
    find_token_id,
    generate_token,
    hash_token,
    require_relay_bearer,
)


class TestRelayToken:
    def test_a_token_id_may_not_contain_a_colon(self) -> None:
        with pytest.raises(ContentError, match="must not contain"):
            RelayToken(id="a:b", token_sha256="0" * 64)

    def test_the_digest_must_be_64_lowercase_hex_characters(self) -> None:
        with pytest.raises(ContentError, match="64 lowercase hex"):
            RelayToken(id="ci", token_sha256="ABCD")
        with pytest.raises(ContentError, match="64 lowercase hex"):
            RelayToken(id="ci", token_sha256="0" * 63)

    def test_round_trips_through_content(self) -> None:
        token = RelayToken(id="ci", token_sha256=hash_token("ci:secret"))
        assert RelayToken.from_content(token.to_content()) == token

    def test_unknown_members_are_rejected(self) -> None:
        with pytest.raises(ContentError, match="unknown members"):
            RelayToken.from_content({"id": "ci", "token_sha256": "0" * 64, "surprise": 1})


class TestGenerateAndFind:
    def test_a_generated_token_carries_its_id_as_a_visible_prefix(self) -> None:
        bearer = generate_token("dashboard")
        assert bearer.startswith("dashboard:")

    def test_find_matches_the_right_id_and_secret(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        assert find_token_id(bearer, tokens) == "ci"

    def test_find_refuses_a_right_id_wrong_secret(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        assert find_token_id("ci:not-the-secret", tokens) is None

    def test_find_refuses_an_id_nobody_configured(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="dashboard", token_sha256=hash_token(bearer)),)
        assert find_token_id(bearer, tokens) is None

    def test_a_token_with_no_colon_is_malformed(self) -> None:
        tokens = (RelayToken(id="ci", token_sha256=hash_token("ci:x")),)
        assert find_token_id("not-a-bearer-token", tokens) is None


class TestRequireRelayBearer:
    def test_no_configured_tokens_leaves_every_method_open(self) -> None:
        require_relay_bearer((), None, "approve")  # does not raise

    def test_a_configured_token_demands_a_bearer(self) -> None:
        tokens = (RelayToken(id="ci", token_sha256=hash_token(generate_token("ci"))),)
        with pytest.raises(RelayAuthError, match="requires Authorization"):
            require_relay_bearer(tokens, None, "approve")

    def test_a_wrong_bearer_is_refused(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        with pytest.raises(RelayAuthError, match="'ci'"):
            require_relay_bearer(tokens, "ci:wrong-secret", "approve")

    def test_the_error_names_the_id_never_the_token(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        try:
            require_relay_bearer(tokens, "ci:wrong-secret", "approve")
        except RelayAuthError as exc:
            assert "wrong-secret" not in str(exc)
            assert bearer not in str(exc)
        else:
            pytest.fail("expected RelayAuthError")

    def test_a_correct_bearer_is_accepted(self) -> None:
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        require_relay_bearer(tokens, bearer, "approve")  # does not raise


class TestBearerFromAuthorization:
    def test_a_bearer_header_is_parsed(self) -> None:
        assert bearer_from_authorization("Bearer ci:secret") == "ci:secret"

    def test_case_insensitive_scheme(self) -> None:
        assert bearer_from_authorization("bearer ci:secret") == "ci:secret"

    def test_no_header_is_none(self) -> None:
        assert bearer_from_authorization(None) is None

    def test_a_different_scheme_is_none(self) -> None:
        assert bearer_from_authorization("Basic dXNlcjpwYXNz") is None

    def test_an_empty_token_is_none(self) -> None:
        assert bearer_from_authorization("Bearer ") is None


class TestRelayTokenStore:
    def test_add_returns_a_token_only_the_hash_is_stored(self, tmp_path: Path) -> None:
        store = RelayTokenStore(tmp_path)
        bearer = store.add("ci")
        assert bearer.startswith("ci:")
        raw = json.loads(store.path.read_text())
        assert raw["format"] == "merkl-relay-tokens-v1"
        assert raw["tokens"] == [{"id": "ci", "token_sha256": hash_token(bearer)}]
        assert bearer not in store.path.read_text()

    def test_the_file_is_not_world_readable(self, tmp_path: Path) -> None:
        store = RelayTokenStore(tmp_path)
        store.add("ci")
        mode = store.path.stat().st_mode & 0o777
        assert mode == stat.S_IRUSR | stat.S_IWUSR

    def test_a_duplicate_id_is_refused(self, tmp_path: Path) -> None:
        store = RelayTokenStore(tmp_path)
        store.add("ci")
        with pytest.raises(ContentError, match="already exists"):
            store.add("ci")

    def test_revoke_removes_it_and_reports_whether_it_existed(self, tmp_path: Path) -> None:
        store = RelayTokenStore(tmp_path)
        store.add("ci")
        assert store.revoke("ci") is True
        assert store.list() == ()
        assert store.revoke("ci") is False

    def test_list_reflects_adds_and_revokes(self, tmp_path: Path) -> None:
        store = RelayTokenStore(tmp_path)
        store.add("ci")
        store.add("dashboard")
        assert {t.id for t in store.list()} == {"ci", "dashboard"}
        store.revoke("ci")
        assert {t.id for t in store.list()} == {"dashboard"}

    def test_an_unconfigured_store_loads_empty(self, tmp_path: Path) -> None:
        assert RelayTokenStore(tmp_path / "does-not-exist-yet").load() == ()

    def test_a_generated_token_round_trips_through_require_relay_bearer(
        self, tmp_path: Path
    ) -> None:
        store = RelayTokenStore(tmp_path)
        bearer = store.add("ci")
        require_relay_bearer(store.load(), bearer, "approve")  # does not raise
        with pytest.raises(RelayAuthError):
            require_relay_bearer(store.load(), "ci:wrong", "approve")
