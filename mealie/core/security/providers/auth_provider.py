import abc
from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy.orm.session import Session

from mealie.core.config import get_app_settings
from mealie.repos.all_repositories import get_repositories
from mealie.schema.user.user import PrivateUser

ALGORITHM = "HS256"
ISS = "mealie"
remember_me_duration = timedelta(days=30)

DURATION_CLAIM = "dur"
"""Total lifetime, in seconds, that this session was granted. Used to renew a token for the same
length it was originally issued for, instead of silently collapsing it down to `TOKEN_TIME`."""


def session_duration(remember_me: bool = False) -> timedelta:
    """The full lifetime of a new login session."""
    settings = get_app_settings()

    duration = timedelta(hours=settings.TOKEN_TIME)
    if remember_me:
        duration = max(remember_me_duration, duration)

    return duration


def renewal_duration(token: str | None) -> timedelta:
    """
    The lifetime to grant when renewing an existing session.

    Sessions slide: renewing re-issues a token for the same total duration the original was
    granted, so a user who keeps using the app never gets logged out. Tokens minted before the
    duration claim existed (and long-lived API tokens, which carry no claim) fall back to the
    configured `TOKEN_TIME`.
    """
    settings = get_app_settings()
    default = timedelta(hours=settings.TOKEN_TIME)

    if not token:
        return default

    try:
        claims = jwt.decode(token, settings.SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return default

    granted = claims.get(DURATION_CLAIM)
    if not isinstance(granted, int) or isinstance(granted, bool) or granted <= 0:
        return default

    # never renew for longer than the longest session a fresh login could hand out
    return min(timedelta(seconds=granted), max(remember_me_duration, default))


class AuthProvider[T](metaclass=abc.ABCMeta):
    """Base Authentication Provider interface"""

    def __init__(self, session: Session, data: T) -> None:
        self.session = session
        self.data = data
        self.user: PrivateUser | None = None
        self.__has_tried_user = False

    @classmethod
    def __subclasshook__(cls, __subclass: type) -> bool:
        return hasattr(__subclass, "authenticate") and callable(__subclass.authenticate)

    def get_access_token(self, user: PrivateUser, remember_me=False) -> tuple[str, timedelta]:
        return AuthProvider.create_access_token({"sub": str(user.id)}, session_duration(remember_me))

    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta | None = None) -> tuple[str, timedelta]:
        settings = get_app_settings()

        to_encode = data.copy()
        expires_delta = expires_delta or timedelta(hours=settings.TOKEN_TIME)

        expire = datetime.now(UTC) + expires_delta

        to_encode["exp"] = expire
        to_encode["iss"] = ISS
        to_encode[DURATION_CLAIM] = int(expires_delta.total_seconds())
        return (
            jwt.encode(to_encode, settings.SECRET, algorithm=ALGORITHM),
            expires_delta,
        )

    def try_get_user(self, username: str) -> PrivateUser | None:
        """Try to get a user from the database, first trying username, then trying email"""
        if self.__has_tried_user:
            return self.user

        db = get_repositories(self.session, group_id=None, household_id=None)

        user = user = db.users.get_one(username, "username", any_case=True)
        if not user:
            user = db.users.get_one(username, "email", any_case=True)

        self.user = user
        return user

    @abc.abstractmethod
    def authenticate(self) -> tuple[str, timedelta] | None:
        """Attempt to authenticate a user"""
        raise NotImplementedError
