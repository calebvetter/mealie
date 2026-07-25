from datetime import timedelta

import jwt
import pytest
from pytest import MonkeyPatch

from mealie.core.config import get_app_settings
from mealie.core.security.providers import auth_provider
from mealie.core.security.providers.auth_provider import (
    ALGORITHM,
    DURATION_CLAIM,
    AuthProvider,
    remember_me_duration,
    renewal_duration,
    session_duration,
)


@pytest.fixture
def token_time(monkeypatch: MonkeyPatch):
    """Sets TOKEN_TIME, in hours, on the cached settings object."""

    def _set(hours: int):
        monkeypatch.setattr(get_app_settings(), "TOKEN_TIME", hours)

    return _set


def test_session_duration_uses_token_time(token_time):
    token_time(48)

    assert session_duration(remember_me=False) == timedelta(hours=48)


def test_remember_me_extends_a_short_token_time(token_time):
    token_time(48)

    assert session_duration(remember_me=True) == remember_me_duration


def test_remember_me_never_shortens_a_long_token_time(token_time):
    token_time(24 * 60)

    assert session_duration(remember_me=True) == timedelta(hours=24 * 60)


def test_access_token_records_the_duration_it_was_granted(token_time):
    token_time(48)

    token, _ = AuthProvider.create_access_token({"sub": "user"}, session_duration(remember_me=True))
    claims = jwt.decode(token, get_app_settings().SECRET, algorithms=[ALGORITHM])

    assert claims[DURATION_CLAIM] == int(remember_me_duration.total_seconds())


def test_renewal_preserves_a_remember_me_session(token_time):
    """Renewing must not silently collapse a 30 day session down to TOKEN_TIME."""
    token_time(48)

    token, _ = AuthProvider.create_access_token({"sub": "user"}, session_duration(remember_me=True))

    assert renewal_duration(token) == remember_me_duration


def test_renewal_preserves_a_regular_session(token_time):
    token_time(48)

    token, _ = AuthProvider.create_access_token({"sub": "user"}, session_duration(remember_me=False))

    assert renewal_duration(token) == timedelta(hours=48)


@pytest.mark.parametrize("token", [None, "", "not-a-jwt"])
def test_renewal_falls_back_to_token_time_for_unusable_tokens(token_time, token):
    token_time(48)

    assert renewal_duration(token) == timedelta(hours=48)


def test_renewal_falls_back_for_tokens_predating_the_duration_claim(token_time):
    token_time(48)

    legacy = jwt.encode(
        {"sub": "user", "exp": 9999999999, "iss": "mealie"},
        get_app_settings().SECRET,
        algorithm=ALGORITHM,
    )

    assert renewal_duration(legacy) == timedelta(hours=48)


def test_renewal_is_capped_at_the_longest_grantable_session(token_time, monkeypatch: MonkeyPatch):
    """A token claiming an implausible duration must not extend a session beyond policy."""
    token_time(48)

    monkeypatch.setattr(auth_provider, "remember_me_duration", timedelta(days=30))
    overlong = jwt.encode(
        {"sub": "user", "exp": 9999999999, DURATION_CLAIM: int(timedelta(days=3650).total_seconds())},
        get_app_settings().SECRET,
        algorithm=ALGORITHM,
    )

    assert renewal_duration(overlong) == timedelta(days=30)
