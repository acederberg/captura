# =========================================================================== #
import json
import traceback
from typing import Annotated, Generator, List, Set

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Mount

# --------------------------------------------------------------------------- #
from captura import __version__, util
from captura.controllers.access import H
from captura.depends import DependsAccess

from .assignments import CollectionAssignmentView, DocumentAssignmentView
from .auth import AuthViewAuth0, AuthViewPytest
from .base import BaseView, OpenApiTagMetadata, OpenApiTags
from .collections import CollectionView
from .documents import DocumentView
from .events import EventView
from .grants import DocumentGrantView, UserGrantView
from .users import UserView

logger = util.get_logger(__name__)

description: str = """
An API for storing, rendering, editting, and sharing text documents and other 
deffered objects. 


## Sharing

Documents can be public or private and owners can grant to other users
the ability to view, modify, or own the document.


## Deffered Objects

Soon the Captura API will support deffering objects to other APIs. More
or less this model will be 'sharing as a service'.
"""


class AppRouteInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    path: Annotated[str, Field()]
    name: Annotated[str, Field()]
    methods: Annotated[Set[H], Field()]


class AppView(BaseView):
    # NOTE: The following are helpful, I don't want to do this right now but
    #       it will be useful for later.
    #
    #       - https://swagger.io/docs/open-source-tools/swagger-ui/usage/configuration/
    #       - https://fastapi.tiangolo.com/how-to/configure-swagger-ui/?h=swagger
    #
    # TODO: Make swagger docs better. Add better examples for requests and
    #       responses, etc.
    #
    #       - https://fastapi.tiangolo.com/reference/openapi/models/
    #
    # NOTE: About static files:
    #
    #       - https://fastapi.tiangolo.com/tutorial/static-files/
    #
    #       I'm aware the using `routes` is a bit taboo, but I think this is a
    #       cleaner pattern.
    routes = []
    if util.path.exists(util.PATH_STATIC):
        view_static = StaticFiles(directory=util.PATH_STATIC)
        routes.append(Mount("/static", view_static))

    view_router = FastAPI(
        title="Captura Document Automation, Sharing, and Organization API.",
        description=description,
        version=__version__,
        contact=dict(
            name="Adrian Cederberg",
            url="https://github.com/acederberg",
            email="adrn.cederberg123@gmail.com",
        ),
        openapi_tags=OpenApiTagMetadata,
        swagger_ui_parameters={"syntaxHighlight.theme": "obsidian"},
        routes=routes,  # type: ignore
        middleware=[
            Middleware(
                SessionMiddleware,
                secret_key=util.SESSION_SECRET,
            )
        ],
    )  # type: ignore

    view_routes = {
        "get_index": {
            "url": "/",
            "tags": [OpenApiTags.html],
            "name": "Index Page",
            "description": "For humans.",
        },
        "get_routes": {
            "url": "/routes",
            "tags": [OpenApiTags.admin],
            "name": "Routes Directory",
            "description": "For text based clients that won't like using help.",
        },
    }
    view_children = {
        # "": EventSearchView,
        "/grants/documents": DocumentGrantView,
        "/grants/users": UserGrantView,
        "/assignments/documents": DocumentAssignmentView,
        "/assignments/collections": CollectionAssignmentView,
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthViewPytest,
        "/events": EventView,
        "": AuthViewAuth0,
    }

    @classmethod
    def get_index(cls, request: Request):
        return cls.view_templates.TemplateResponse(request, "index.j2", {})

    @classmethod
    def get_routes(
        cls,
        access: DependsAccess,
        methods: Set[H] | None = None,
        names: Set[str] | None = None,
        names_fragment: str | None = None,
        paths_fragment: str | None = None,
    ) -> List[AppRouteInfo]:
        if not access.token:
            raise HTTPException(403, detail="Token required.")

        # NOTE: Type ignored for metaclass considerations.
        items: Generator[APIRoute, None, None]
        items = (
            item
            for item in cls.view_router.routes  # type: ignore
            if isinstance(item, APIRoute)
        )

        if methods is not None:
            items = (
                item
                for item in items
                if all(method in methods for method in item.method)  # type: ignore
                # hasattr(item, "methods")
                # and
            )

        match (names, names_fragment):
            case (set(), None):
                items = (item for item in items if item.name in names)  # type: ignore
            case (None, str()):
                items = (item for item in items if names_fragment in item.name)
            case (None, None):
                pass
            case _:
                msg = "Only one of `names` and `names_fragment` may be "
                msg += "specified."
                raise HTTPException(422, detail=dict(msg=msg))

        if paths_fragment is not None:
            items = (item for item in items if paths_fragment in item.path)

        t = TypeAdapter(List[AppRouteInfo])
        return t.validate_python(items)


# =========================================================================== #


# TODO: The traceback should not show up in prod unless the status `500`.
#       In fact, the traceback should be stored by the logger instead.
# TODO: Figure out how to use config to turn this on or off. Unfortunately
#       exception handlers do not use dependencies and it is hard to build
#       dependecies from the request directly.
@AppView.view_router.exception_handler(HTTPException)  # type: ignore
async def http_exception_handler(request: Request, exc: HTTPException):
    # https://github.com/encode/uvicorn/blob/master/uvicorn/protocols/http/h11_impl.py
    if util.VERBOSE_HTTPEXCEPTIONS:
        traceback.print_exc()

    if util.VERBOSE:
        if request.client:
            host, port = request.client.host, request.client.port
            logger.info("%s:%s - %s", host, port, json.dumps(exc.detail, indent=2))
        else:
            logger.debug("No client for request.")

    return JSONResponse(
        exc.detail,
        exc.status_code,
    )


__all__ = (
    "DocumentGrantView",
    "UserGrantView",
    "CollectionView",
    "EventView",
    "DocumentView",
    "UserView",
    "BaseView",
)
