"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.

"""

from http import HTTPMethod
import logging
from typing import (
    Any,
    ClassVar,
    Dict,
)

from fastapi import (
    APIRouter,
)
from fastapi.routing import APIRoute

from app import __version__, util


logger = util.get_logger(__name__)
logger.level = logging.INFO


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


class BaseView(ViewMixins, metaclass=ViewMeta):
    ...
