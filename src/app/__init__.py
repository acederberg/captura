__version__ = "0.1.0"

from . import hooks
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

app = AppView.view_router
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
