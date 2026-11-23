"""``pytrat demo``: the payment-transfer story, runnable straight after ``pip install``.

The end-to-end security assertions live in ``tests/integration/test_payment_demo.py``; these tests
check the command itself.
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pytrat.cli import app
from pytrat.cli._demo import narrative
from pytrat.cli._demo.lab import KEY_NAMES, Lab, Urls

runner = CliRunner()


def test_demo_records_the_honest_transfer_and_refuses_the_tampered_one() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0, result.output
    assert "201 recorded 100.00 USD" in result.output
    assert "403 refused (TRANSACTION_CONTEXT_MISMATCH)" in result.output
    assert "✔ the tampered $9,000.00 transfer was refused" in result.output
    assert '"event_type": "authorization.denied"' in result.output


def test_demo_never_prints_a_token() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0, result.output
    # Every compact JWS starts with a base64url-encoded JSON header: '{"' encodes to "eyJ".
    assert "eyJ" not in result.output


def test_demo_without_audit_hides_the_audit_event() -> None:
    result = runner.invoke(app, ["demo", "--no-audit"])
    assert result.exit_code == 0, result.output
    assert "audit event" not in result.output


def test_demo_fails_loudly_when_the_story_does_not_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(*, show_audit: bool) -> bool:
        return False

    monkeypatch.setattr(narrative, "run_demo", broken)
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 1
    assert "did not behave as expected" in result.output


class TestLabLoad:
    """``Lab.load`` backs the Docker Compose deployment, where each container holds its own keys."""

    def _provision(self, tmp_path: Path) -> tuple[Path, Path, Path]:
        generated = Lab.create(tmp_path / "generated")
        public = tmp_path / "public"
        public.mkdir()
        for name in KEY_NAMES:
            jwks = json.dumps(generated.public_jwks(name))
            (public / f"{name}.jwks.json").write_text(jwks, encoding="utf-8")
        ca_bundle = public / "ca.pem"
        ca_bundle.write_text("not used until a TLS context is built", encoding="utf-8")
        return generated.key_directory, public, ca_bundle

    def test_holds_only_the_private_keys_present(self, tmp_path: Path) -> None:
        key_directory, public, ca_bundle = self._provision(tmp_path)
        for name in KEY_NAMES:
            if name != "payment-service":
                (key_directory / f"{name}.pem").unlink()
        lab = Lab.load(
            directory=tmp_path / "work",
            key_directory=key_directory,
            public_directory=public,
            urls=Urls(),
            ca_bundle=ca_bundle,
        )
        assert set(lab.keys) == {"payment-service"}
        assert set(lab.public_keys) == set(KEY_NAMES)

    def test_missing_ca_bundle_is_refused(self, tmp_path: Path) -> None:
        key_directory, public, _ = self._provision(tmp_path)
        with pytest.raises(FileNotFoundError, match="CA bundle"):
            Lab.load(
                directory=tmp_path / "work",
                key_directory=key_directory,
                public_directory=public,
                urls=Urls(),
                ca_bundle=tmp_path / "absent.pem",
            )

    def test_jwks_holding_the_wrong_key_is_refused(self, tmp_path: Path) -> None:
        key_directory, public, ca_bundle = self._provision(tmp_path)
        (public / "tts.jwks.json").write_text(
            (public / "idp.jwks.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        with pytest.raises(FileNotFoundError, match=r"tts\.jwks\.json"):
            Lab.load(
                directory=tmp_path / "work",
                key_directory=key_directory,
                public_directory=public,
                urls=Urls(),
                ca_bundle=ca_bundle,
            )

    def test_tls_trusts_only_the_given_ca(self, tmp_path: Path) -> None:
        assert Lab.create(tmp_path).tls_verify() is True
        lab = Lab(
            directory=tmp_path,
            urls=Urls(),
            keys={},
            public_keys={},
            key_directory=tmp_path,
            ca_bundle=tmp_path / "ca.pem",
        )
        (tmp_path / "ca.pem").write_text("not a certificate", encoding="utf-8")
        with pytest.raises(ssl.SSLError):  # proves the bundle, not the system store, is loaded
            lab.tls_verify()
