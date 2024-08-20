"""Api routers and functions.
This includes a metaclass so that undecorated functions may be tested.

"""

# =========================================================================== #
import enum
from http import HTTPMethod
from os import path
from typing import Any, ClassVar, Dict, Literal

from fastapi import APIRouter
from fastapi.templating import Jinja2Templates

# --------------------------------------------------------------------------- #
from captura import util
from captura.err import AnyErrDetailAccessDocumentGrant, ErrDetail, ErrObjMinSchema

logger = util.get_logger(__name__)
# logger.level = logging.INFO


class OpenApiTags(str, enum.Enum):
    users = "users"
    documents = "documents"
    collections = "collections"
    edits = "edits"
    grants = "grants"
    assignments = "assignments"
    events = "events"

    # etc
    auth0 = "auth0"
    admin = "admin"
    html = "html"


OpenApiTagMetadata = [
    {
        "name": "users",
        "description": "View and Manage Users.",
    },
    {
        "name": "documents",
        "description": "View and Manage Documents.",
    },
    {
        "name": "collections",
        "description": "View and Manage Collections.",
    },
    {
        "name": "grants",
        "description": "View and manage document access and access invitations.",
    },
    {
        "name": "assignments",
        "description": "View and manage assignments of documents to collections.",
    },
    {
        "name": "events",
        "description": "View and manage object events.",
    },
    {"name": "auth0", "description": "Auth0 and token tools."},
    {
        "name": "html",
        "description": "For humans.",
    },
]

OpenApiResponseCommon = {
    404: dict(
        model=ErrDetail[ErrObjMinSchema],
        description="Object could not be found.",
    ),
    410: dict(
        model=ErrDetail[ErrObjMinSchema],
        detail="Object is deleted or is pending deletion.",
    ),
}
OpenApiResponseUnauthorized = {
    401: dict(
        model=ErrDetail[Literal["Token required"]],
    ),
}
OpenApiResponseDocumentForbidden = {
    403: dict(
        model=AnyErrDetailAccessDocumentGrant,
        description=(
            "For read, cannot access document because no grants exist and "
            "the document is private. Otherwise grants do not exist or they "
            "are pending."
        ),
    ),
}


class ViewMixins:
    """

    :attr view_children: Dictionary of instances to instances.
    :attr view_router: The router built by :class:`ViewMeta`.
    :attr view: Mapping from router function names to router routes.
    """

    # view_children: ClassVar[Dict[str, Type]] = dict()
    view_children: ClassVar[Dict[str, "ViewMeta"]] = dict()
    view_router: ClassVar[APIRouter]
    view_router_args: ClassVar[Dict[str, Any]] = dict()  # type: ignore
    view_routes: ClassVar[Dict[str, str | Dict[str, Any]]] = dict()  # type: ignore
    view_templates: ClassVar[Jinja2Templates] = Jinja2Templates(
        directory=path.join(path.dirname(__file__), "templates")
    )


class ViewMeta(type):
    """Metaclass to handle routing.

    It will build a router under `view`.
    """

    @classmethod
    def add_route(cls, T, fn_name: str, fn_info_raw: str | Dict[str, Any]):
        name = T.__name__

        # NOTE: Annotation is stange bc of the following mypy error:
        #       Incompatible types in capture pattern (pattern captures type "dict[object, object]", variable has type "dict[str, Any]")  [misc]
        info: Dict[Any, Any]
        url: str
        match fn_info_raw:
            case str() as url:
                info = dict()
            case {"url": url, **info}:
                ...
            case bad:
                msg = "Invalid info for url: Expected `str` for url or "
                msg += f"`dict` specifying atleast a url, got `{bad}`."
                raise ValueError(msg)

        # Parse name
        raw, _ = fn_name.split("_", 1)
        http_meth = next((hh for hh in HTTPMethod if hh.value.lower() == raw), None)
        if http_meth is None:
            logger.warning(f"Could not determine method of `{fn_name}`.")
            return

        # Update status code if not provided.
        if http_meth == HTTPMethod.POST and "status" not in info:
            info.update(status_code=201)

        # Find attr
        fn = getattr(T, fn_name, None)
        if fn is None:
            msg = f"No such method `{fn_name}` of `{name}`."
            raise ValueError(msg)

        # Get the decoerator and call it.
        logger.debug("Adding function `%s` at url `%s`.", fn.__name__, url)
        decorator = getattr(T.view_router, http_meth.value.lower())
        decorator(url, **info)(fn)

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
            for fn_name, fn_info in T.view_routes.items():  # type: ignore
                cls.add_route(T, fn_name, fn_info)

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
