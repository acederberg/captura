__version__ = "0.1.7"

from fastapi import FastAPI

from . import hooks, util
from .auth import Auth
from .config import Config
from .models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenCollection,
    ChildrenDocument,
    ChildrenUser,
    Collection,
    Document,
    KindEvent,
    KindObject,
    Level,
    LevelStr,
    Tables,
    User,
)
from .views import AppView

app: FastAPI = AppView.view_router  # type: ignore

if util.PATH_HOOKS_USE:
    hooks.do_hooks(AppView)


__all__ = (
    # Application
    "Auth",
    "Config",
    "AppView",
    # Models
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "Tables",
    "KindEvent",
    "KindObject",
    "Level",
    "LevelStr",
    "KindObject",
    "ChildrenUser",
    "ChildrenCollection",
    "ChildrenDocument",
)
