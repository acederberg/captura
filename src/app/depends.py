"""This module contains all of the depends that will be needed in variou
endpoints.

The code behind most of the functions here should be in other modules, for
instance `auth` or `config`, except in the case that it is dependency used to
trap and transform api parameters. No exports (things in ``__all__``) should
be wrapped in ``Depends``.
"""
from datetime import datetime
from functools import cache
from typing import Annotated, Any, Callable, Dict, TypeAlias

import jwt
from fastapi import Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from typing import Tuple
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app import util
from app.auth import Auth
from app.config import Config
from app.models import User

# NOTE: `cache` is used instead of using the `use_cache` keyword argument of
#       `Depends` because it will result in identical object ids. For instance
#       this means that `session_maker` will always return the same session
#       maker.

logger = util.get_logger(__name__)


@cache
def config() -> Config:
    """The configuration dependency function.

    This function should only run once. I do not know if it is better to use
    ``functolls.cache`` or to use the ``cache`` keyword of ``fastapi.Depends``.
    The logging statement is used to make sure that the internals of this
    function are only called once.

    :returns: Application configuration. See :class:`Config`.
    """
    logger.debug("Dependency `config` called.")
    return Config()  # type: ignore


DependsConfig: TypeAlias = Annotated[Config, Depends(config, use_cache=False)]


@cache
def engine(config: DependsConfig) -> Engine:
    """The engine dependency function.

    Note that bringing in a database connector is a supported dependency
    pattern, for instance look at this:

    .. code:: txt

        https://fastapi.tiangolo.com/tutorial/sql-databases/

    :param config: Configuration specifying the MySQL host.
    :returns: An ``sqlalchemy.engine.Engine`` instance connected to the
        host as specified by :param:`config`.
    """
    logger.debug("Dependency `engine` called.")
    return config.engine()


DependsEngine: TypeAlias = Annotated[Engine, Depends(engine, use_cache=False)]


@cache
def session_maker(engine: DependsEngine) -> sessionmaker[Session]:
    """
    :param engine: An ``sqlalchemy.engine``, probably from :func:`engine`.
    :returns: A ``sqlalchemy.orm.sessionmaker`` for creating sessions.
    """
    logger.debug("Dependency `session_maker` called.")
    return sessionmaker(engine)


DependsSessionMaker: TypeAlias = Annotated[
    sessionmaker[Session], Depends(session_maker, use_cache=False)
]


# =========================================================================== #
# Authentication dependencies.


@cache
def auth(
    config: DependsConfig,
) -> Auth:
    """
    :param: Application configuration. Specifies ``auth0`` configuration.
    :returns: The authentication handler defined in :module:`.auth` for
        ``auth0`` specified by :param:``.
    """

    logger.debug("Dependency `auth` called.")
    return (Auth.forAuth0 if config.auth0.use else Auth.forPyTest)(config)


DependsAuth: TypeAlias = Annotated[Auth, Depends(auth, use_cache=False)]


def try_decode(
    auth,
    authorization,
) -> Tuple[Dict[str, str], HTTPException | None]:
    try:
        return auth.decode(authorization), None
    except jwt.DecodeError:
        _msg = "Failed to decode bearer token."
    except jwt.InvalidAudienceError:
        _msg = "Invalid bearer token audience."
    except jwt.InvalidIssuerError:
        _msg = "Invalid bearer token issuer."
    except jwt.InvalidTokenError:
        _msg = "Invalid bearer token."
    except ValueError as err:
        _msg = err.args[0]
    return None, HTTPException(401, detail="Invalid Token: " + _msg)


@cache
def token(
    auth: DependsAuth,
    authorization: Annotated[str, Header()],
) -> Dict[str, str]:
    """Decode and deserialize the bearer JWT specified in the ``Authorization``
    header.

    :param config: Application configuration.
    :param auth: Auth0 or PyTest authorization handler.
    :param authorization: Authorization header. It should match
        :const:`PATTERN_BEARER`.
    """
    decoded, err = try_decode(auth, authorization)
    if err is not None:
        raise err
    return decoded


def token_optional(
    auth: DependsAuth,
    authorization: Annotated[str | None, Header()] = None,
) -> Dict[str, str] | None:
    if authorization is not None:
        return token(auth, authorization)
    return None


DependsTokenOptional: TypeAlias = Annotated[
    Dict[str, str],
    Depends(token_optional),
]
DependsToken: TypeAlias = Annotated[Dict[str, str], Depends(token)]


def uuid(token: DependsToken, uuid: str | None = None) -> str:
    """Get the user UUID either from the token or get the uuid from query
    parameters.

    Be careful when using this on endpoints that specific to one user.
    """
    return uuid if uuid is not None else token["uuid"]


DependsUUID: TypeAlias = Annotated[str, Depends(uuid)]


# NOTE: Caching should make it such that this function is not invoked multiple
#       times when making multiple requests. If the same JWT is decoded,
#       verified, and deserialized on each request by a user a certain overhead
#       will be added to every request when this might not be necessary.
#
#       There is a potential problem with caching, which is that multiple user
#       tokens will be persisted in memory, which could be a vulnerability that
#       might allow 'intruders' into deployments to potentially get a hold of
#       user tokens. Of course, if such a 'hacker' had access to the
#       deployment, the game is over.
@cache
def user(
    config: DependsConfig,
    sessionmaker: DependsSessionMaker,
    token: DependsToken,
) -> User:
    """ """
    uuid = token.get("uuid_user")
    if uuid is None:
        raise HTTPException(
            401,
            detail="Invalid token: Token does not specify a user uuid.",
        )

    logger.debug("Dependency `auth` called for user with uuid `%s`.", uuid)

    with sessionmaker() as session:
        user = session.execute(select(User).where(User.uuid == uuid)).scalar()

        if user is None:
            raise HTTPException(
                401,
                detail="Invalid Token: User does not exist.",
            )

    return user


DependsUser: TypeAlias = Annotated[User, Depends(user)]


# =========================================================================== #


class Filter(BaseModel):
    limit: int = 10
    pattern: None | str = None
    # NOTE: Tagging would be helpful
    # tag: None | str = None


DependsFilter: TypeAlias = Annotated[Filter, Depends()]
