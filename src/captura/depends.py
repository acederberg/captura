"""This module contains all of the depends that will be needed in variou
endpoints.

The code behind most of the functions here should be in other modules, for
instance `auth` or `config`, except in the case that it is dependency used to
trap and transform api parameters. No exports (things in ``__all__``) should
be wrapped in ``Depends``.
"""

# =========================================================================== #
from functools import cache
from typing import Annotated, TypeAlias

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.ext.asyncio.session import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session, sessionmaker

# --------------------------------------------------------------------------- #
from captura import util
from captura.auth import Auth, Token, TokenPermissionTier, try_decode
from captura.config import Config
from captura.controllers.access import Access
from captura.controllers.create import Create, Update
from captura.controllers.delete import Delete
from captura.controllers.read import Read
from captura.models import User
from captura.views.args import QueryForce

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


_DependsConfig = Depends(config, use_cache=False)
DependsConfig: TypeAlias = Annotated[Config, _DependsConfig]


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


@cache
def async_engine(config: DependsConfig) -> AsyncEngine:
    logger.debug("Dependency `engine` called.")
    return config.async_engine()


DependsEngine: TypeAlias = Annotated[Engine, Depends(engine, use_cache=False)]
DependsAsyncEngine: TypeAlias = Annotated[
    AsyncEngine, Depends(async_engine, use_cache=False)
]


@cache
def session_maker(engine: DependsEngine) -> sessionmaker[Session]:
    """
    :param engine: An ``sqlalchemy.engine``, probably from :func:`engine`.
    :returns: A ``sqlalchemy.orm.sessionmaker`` for creating sessions.
    """
    logger.debug("Dependency `session_maker` called.")
    return sessionmaker(engine)


@cache
def async_session_maker(
    async_engine: DependsAsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """
    :param engine: An ``sqlalchemy.engine``, probably from :func:`engine`.
    :returns: A ``sqlalchemy.orm.sessionmaker`` for creating sessions.
    """
    logger.debug("Dependency `session_maker` called.")
    return async_sessionmaker(bind=async_engine, class_=AsyncSession)


DependsSessionMaker: TypeAlias = Annotated[
    sessionmaker[Session],
    Depends(session_maker),
]
DependsAsyncSessionMaker: TypeAlias = Annotated[
    async_sessionmaker[AsyncSession],
    Depends(async_session_maker),
]


# =========================================================================== #
# Authentication dependencies.


@cache
def auth(config: DependsConfig) -> Auth:
    """
    :param: Application configuration. Specifies ``auth0`` configuration.
    :returns: The authentication handler defined in :module:`.auth` for
        ``auth0`` specified by :param:``.
    """

    logger.debug("Dependency `auth` called.")
    return (Auth.forAuth0 if config.auth0.use else Auth.forPyTest)(config)


DependsAuth: TypeAlias = Annotated[Auth, Depends(auth, use_cache=False)]

HeaderAuthorization = Annotated[str, Header(description="Auth0 bearer token.")]
HeaderAuthorizationOptional = Annotated[
    str | None, Header(description="Optional auth0 bearer token.")
]


@cache
def token(
    auth: DependsAuth,
    authorization: HeaderAuthorization,
) -> Token:
    """Decode and deserialize the bearer JWT specified in the ``Authorization``
    header.

    Database validation happens later once a database session is available.

    :param config: Application configuration.
    :param auth: Auth0 or PyTest authorization handler.
    :param authorization: Authorization header. It should match
        :const:`PATTERN_BEARER`.
    """
    decoded, err = try_decode(auth, authorization)
    if err is not None:
        raise err
    token = Token.model_validate(decoded)
    return token


def token_optional(
    auth: DependsAuth,
    authorization: HeaderAuthorizationOptional = None,
) -> Token | None:
    if authorization is not None:
        return token(auth, authorization)
    return None


def token_admin(_token: "DependsToken"):
    token = Token.model_validate(_token)
    if token.tier != TokenPermissionTier.admin:
        raise HTTPException(403, detail="Admin only.")

    return token


DependsTokenOptional: TypeAlias = Annotated[
    None | Token,
    Depends(token_optional),
]
DependsToken: TypeAlias = Annotated[Token, Depends(token)]
DependsTokenAdmin: TypeAlias = Annotated[Token, Depends(token_admin)]


def uuid(token: DependsToken, uuid: str | None = None) -> str:
    """Get the user UUID either from the token or get the uuid from query
    parameters.

    Be careful when using this on endpoints that specific to one user.
    """
    return uuid if uuid is not None else token.subject


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
    uuid = token.subject
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

# --------------------------------------------------------------------------- #


def access(
    sessionmaker: DependsSessionMaker,
    token: DependsTokenOptional,
    request: Request,
):
    logger.debug("Creating sessionmaker access.")
    with sessionmaker() as session:
        yield Access(session=session, token=token, method=request.method)
        logger.debug("Exitting `sessionmaker` context.")


DependsAccess: TypeAlias = Annotated[Access, Depends(access)]


def create(
    token: DependsTokenOptional,
    access: DependsAccess,
    request: Request,
    force: QueryForce = False,
) -> Create:
    api_origin = request.url.path
    return Create(
        force=force,
        session=access.session,
        token=token,
        method=request.method,
        api_origin=api_origin,
    )


def read(
    token: DependsTokenOptional,
    access: DependsAccess,
    request: Request,
) -> Read:
    return Read(session=access.session, token=token, method=request.method)


def api_origin(request: Request) -> str:
    return f"{request.method} {request.url.path}"


DependsApiOrigin = Annotated[str, Depends(api_origin)]


def update(
    token: DependsTokenOptional,
    access: DependsAccess,
    request: Request,
    api_origin: DependsApiOrigin,
    force: QueryForce = False,
) -> Update:
    return Update(
        session=access.session,
        token=token,
        method=request.method,
        api_origin=api_origin,
        force=force,
    )


def delete(
    token: DependsTokenOptional,
    access: DependsAccess,
    request: Request,
    api_origin: DependsApiOrigin,
    force: QueryForce = False,
) -> Delete:
    return Delete(
        session=access.session,
        token=token,
        method=request.method,
        api_origin=api_origin,
        access=access,
        force=force,
    )


DependsCreate: TypeAlias = Annotated[Create, Depends(create)]
DependsRead: TypeAlias = Annotated[Read, Depends(read)]
DependsUpdate: TypeAlias = Annotated[Update, Depends(update)]
DependsDelete: TypeAlias = Annotated[Delete, Depends(delete)]
