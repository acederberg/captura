from .grants import GrantView
from .assignments import AssignmentView
from .collections import CollectionView
from .grants import GrantView
from .auth import AuthView
from .events import EventView
from .documents import DocumentView
from .users import UserView
from fastapi import FastAPI
from .base import BaseView
from app.depends import DependsSessionMaker


class AppView(BaseView):
    view_router = FastAPI()  # type: ignore
    view_routes = {"get_index": "/"}
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
