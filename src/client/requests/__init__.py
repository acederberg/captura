import enum
from typing import Tuple

import httpx
import typer
from client import flags
from client.flags import Output
from client.handlers import CONSOLE

from .assignments import AssignmentRequests
# from .assignments import AssignmentRequests
from .base import BaseRequests
from .collections import CollectionRequests
from .documents import DocumentRequests
from .events import EventsRequests
from .grants import GrantRequests
from .tokens import TokenRequests
from .users import UserRequests


# NOTE: All enums pertaining to tables should use the plural table names as
#       enum names.
class RequestsEnum(enum.Enum):
    users = UserRequests
    collections = CollectionRequests
    documents = DocumentRequests
    events = EventsRequests
    tokens = TokenRequests


__all__ = (
    "UserRequests",
    "CollectionRequests",
    "DocumentRequests",
    "GrantRequests",
    "AssignmentRequests",
    "EventsRequests",
    "RequestsEnum",
    "BaseRequests",
)
