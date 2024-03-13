import traceback
from typing import Annotated, Generator, List, Set

from app import __version__
from app.auth import Auth
from app.controllers.access import Access, H
from app.depends import DependsAccess, DependsAuth, DependsSessionMaker
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .assignments import CollectionAssignmentView, DocumentAssignmentView
from .auth import AuthView
from .base import BaseView, OpenApiTagMetadata, OpenApiTags
from .collections import CollectionView
from .documents import DocumentView
from .events import EventSearchView, EventView
from .grants import DocumentGrantView, UserGrantView
from .users import UserSearchView, UserView


class AppRouteInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    path: Annotated[str, Field()]
    name: Annotated[str, Field()]
    methods: Annotated[Set[H], Field()]


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


class AppView(BaseView):
    # NOTE: The following are helpful, I don't want to do this right now but
    #       it will be useful for later.
    #
    #       - https://swagger.io/docs/open-source-tools/swagger-ui/usage/configuration/
    #       - https://fastapi.tiangolo.com/how-to/configure-swagger-ui/?h=swagger
    #
    # TODO: Make swagger docs better. Add better examples for requests and
    #       responses, etc.
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
    )  # type: ignore

    # TODO: This should not show up in prod unless the status `500`. In fact,
    #       the traceback should be stored somewhere.
    @view_router.exception_handler(HTTPException)  # type: ignore
    async def http_exception_handler(request, exc: HTTPException):
        traceback.print_exc()
        return JSONResponse(
            exc.detail,
            exc.status_code,
        )

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
        "": EventSearchView,
        "/grants/documents": DocumentGrantView,
        "/grants/users": UserGrantView,
        "/assignments/documents": DocumentAssignmentView,
        "/assignments/collections": CollectionAssignmentView,
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthView,
        "/events": EventView,
    }

    @classmethod
    def get_index(cls, access: DependsAccess) -> str:
        return "It works!"

    @classmethod
    def get_routes(
        cls,
        access: DependsAccess,
        methods: Set[H] | None = None,
        names: Set[str] | None = None,
        names_fragment: str | None = None,
        paths_fragment: str | None = None,
    ) -> List[AppRouteInfo]:
        if not access.token.admin:
            raise HTTPException(403, detail="Admins only.")

        # NOTE: Type ignored for metaclass considerations.
        items: Generator[APIRoute, None, None]
        items = (item for item in cls.view_router.routes)  # type: ignore

        if methods is not None:
            items = (
                item
                for item in items
                if all(method in methods for method in item.method)
            )

        match (names, names_fragment):
            case (set(), None):
                items = (item for item in items if item.name in names)
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


__all__ = (
    "DocumentGrantView",
    "UserGrantView",
    "AssignmentView",
    "CollectionView",
    "AuthView",
    "EventView",
    "DocumentView",
    "UserView",
    "BaseView",
)
