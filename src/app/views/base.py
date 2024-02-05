"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.

"""

import logging
from functools import cached_property
from http import HTTPMethod
from typing import Any, ClassVar, Dict, Set, Tuple, Type, TypeVar

from app import __version__, util
from app.auth import Token
from app.depends import DependsToken
from app.models import (
    AnyModel,
    Assignment,
    Collection,
    Document,
    Level,
    LevelHTTP,
    ResolvableSingular,
    User,
)
from fastapi import APIRouter, HTTPException
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

logger = util.get_logger(__name__)
logger.level = logging.INFO

# =========================================================================== #
# Controllers

T_BaseController = TypeVar("T_BaseController", bound="BaseController")


class BaseController:
    """This is going to be required.

    :attr method: The ``http.HTTPMethod``. In some controllers this will be
        constant. In the access controller this will be used to check the
        levels of grants required to perform particular operations.
    :attr session: A ``Session``.
    :attr token: A ``_token``.
    """

    method: HTTPMethod
    session: Session
    _token: Token | None

    @property
    def level(self) -> Level:
        print(LevelHTTP._value2member_map_)
        return LevelHTTP[self.method.name].value

    @cached_property
    def token(self) -> Token:
        if self._token is None:
            raise HTTPException(401, detail="Token required.")
        return self._token

    @cached_property
    def token_user(self) -> User:
        return User.if_exists(self.session, self.token.uuid)

    def then(self, type_: Type[T_BaseController], **kwargs) -> T_BaseController:
        "For chainable controllers."
        return type_(self.session, self._token, self.method, **kwargs)

    def token_user_or(
        self,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> User:
        return (
            User.resolve(self.session, resolve_user)
            if resolve_user is not None
            else self.token_user
        )

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
    ):
        self.session = session
        match method:
            case str():
                self.method = HTTPMethod(method)
            case HTTPMethod():
                self.method = method
            case _:
                raise ValueError(f"Invalid input `{method}` for method.")

        match token:
            case dict() | None as raw:
                self._token = None if raw is None else Token.model_validate(raw)
            case Token() as token:
                self._token = token


class ForceController(BaseController):

    force: bool = True

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        force: bool = True,
    ):
        super().__init__(session, token, method)
        self.force = force

    # NOTE: Will be needed by delete and upsert both.
    def split_assignment_uuids(
        self,
        source: Collection | Document,
        uuid_target: Set[str],
    ) -> Tuple[Set[str], Set[str]]:
        """If"""
        kind_source = source.__class__.__tablename__
        is_doc = kind_source == "documents"
        kind_target = "collections" if is_doc else "documents"

        uuid_deleted, uuid_active = Assignment.split(
            self.session,
            source,
            uuid_target,
        )

        if uuid_deleted and not self.force:
            raise HTTPException(
                400,
                detail=dict(
                    uuid_user=self.token.uuid,
                    kind_source=kind_source,
                    uuid_source=source.uuid,
                    kind_target=kind_target,
                    uuid_target=uuid_target,
                    msg="Assignments must be hard deleted to re-`POST`.",
                ),
            )

        return uuid_deleted, uuid_active


# =========================================================================== #
# Views


class ViewMixins:
    """

    :attr view_children: Dictionary of instances to instances.
    :attr view_router: The router built by :class:`ViewMeta`.
    :attr view: Mapping from router function names to router routes.
    """

    # view_children: ClassVar[Dict[str, Type]] = dict()
    view_children: ClassVar[Dict[str, "ViewMeta"]] = dict()
    view_router: ClassVar[APIRouter]
    view_router_args: ClassVar[Dict[str, Any]] = dict()
    view_routes: ClassVar[Dict[str, str]] = dict()


class ViewMeta(type):
    """Metaclass to handle routing.

    It will build a router under `view`.
    """

    @classmethod
    def add_route(cls, T, name_fn: str, route: APIRoute):
        name = T.__name__

        # Parse name
        raw, _ = name_fn.split("_", 1)
        http_meth = next((hh for hh in HTTPMethod if hh.value.lower() == raw), None)
        if http_meth is None:
            logger.warning(f"Could not determine method of `{name_fn}`.")
            return

        # Find attr
        fn = getattr(T, name_fn, None)
        if fn is None:
            msg = f"No such method `{name_fn}` of `{name}`."
            raise ValueError(msg)

        # Create decorator kwargs
        kwargs = dict()
        if http_meth == HTTPMethod.POST:
            kwargs.update(status_code=201)

        # kwargs.update(views_route_args)

        # Get the decoerator and call it.
        logger.debug("Adding function `%s` at route `%s`.", fn.__name__, route)
        decorator = getattr(T.view_router, http_meth.value.lower())
        decorator(route, **kwargs)(fn)

    def __new__(cls, name, bases, namespace):
        T = super().__new__(cls, name, bases, namespace)
        logger.debug("Validating `%s` router.", name)

        # Validate `view_children`.
        if not hasattr(T, "view_children"):
            raise ValueError(f"`{name}` must define `view_children`.")
        elif not isinstance(T.view_children, dict):  # type: ignore
            raise ValueError(f"`{name}.view_children` must be a `dict`.")

        # Validate `view`.
        if not hasattr(T, "view_routes"):
            raise ValueError(f"`{name}` must define `view`.")
        elif not isinstance(T.view_routes, dict):  # type: ignore
            raise ValueError(f"`{name}.view` must be a dict.")

        # Validate `view_router_args`.
        if not hasattr(T, "view_router_args"):
            raise ValueError(f"`{name}` must define `view_router_args`.")
        elif not isinstance(T.view_router_args, dict):  # type: ignore
            raise ValueError(f"`{name}.view_router_args` must be a `dict`.")

        if name != "BaseView":
            # Create router.
            logger.debug("Creating router for `%s`.", name)
            T.view_router = (  # type: ignore
                T.view_router  # type: ignore
                if hasattr(T, "view_router")
                else APIRouter(**T.view_router_args)  # type: ignore
            )
            for name_fn, route in T.view_routes.items():  # type: ignore
                cls.add_route(T, name_fn, route)

            for child_prefix, child in T.view_children.items():  # type: ignore
                logger.debug(
                    "Adding child router `%s` for `%s`.",
                    child_prefix,
                    name,
                )
                T.view_router.include_router(  # type: ignore
                    child.view_router,
                    prefix=child_prefix,
                )

        return T


class BaseView(ViewMixins, metaclass=ViewMeta): ...
