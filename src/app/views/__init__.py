from typing import Annotated, Generator, List, Set

from app.auth import Auth
from app.controllers.access import H
from app.depends import DependsAccess, DependsAuth, DependsSessionMaker
from fastapi import FastAPI, HTTPException
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .assignments import AssignmentView
from .auth import AuthView
from .base import BaseView
from .collections import CollectionView
from .documents import DocumentView
from .events import EventView
from .grants import GrantView
from .users import UserSearchView, UserView


class AppRouteInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    path: Annotated[str, Field()]
    name: Annotated[str, Field()]
    methods: Annotated[Set[H], Field()]


class AppView(BaseView):
    view_router = FastAPI()  # type: ignore
    view_routes = {
        "get_index": "/",
        "get_routes": "/routes",
    }
    view_children = {
        "/grants": GrantView,
        "/assignments": AssignmentView,
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthView,
        "/events": EventView,
    }

    @classmethod
    def get_index(cls, uuid: int, makesession: DependsSessionMaker) -> None:
        ...

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
        items = (item for item in cls.view_router.routes) # type: ignore

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
    "GrantView",
    "AssignmentView",
    "CollectionView",
    "GrantView",
    "AuthView",
    "EventView",
    "DocumentView",
    "UserView",
    "BaseView",
)
