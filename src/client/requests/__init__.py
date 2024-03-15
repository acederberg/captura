import enum
from typing import Tuple

import httpx
import typer
from client import flags
from client.flags import Output
from client.handlers import CONSOLE

# from .assignments import AssignmentRequests
from .base import BaseRequest
from .collections import CollectionRequests
from .documents import DocumentRequests
from .events import EventsRequests
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


class Requests(BaseRequest):
    command = "main"
    commands = tuple()
    children = tuple(rr.value for rr in RequestsEnum)

    users: UserRequests
    collections: CollectionRequests
    documents: DocumentRequests
    events: EventsRequests
    tokens: TokenRequests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for child in self.children:
            child = RequestsEnum._value2member_map_[child]
            setattr(self, child.name, child.value.from_(self))

    def update_token(self, token: str):
        self._token = token
        for ee in RequestsEnum:
            requester = getattr(self, ee.name)
            requester._token = token

    def callback(
        self,
        output: flags.FlagOutput = Output.table,
        columns: flags.FlagColumns = list(),
        *,
        profile: flags.FlagProfile = None,
        host: flags.FlagHost = None,
    ) -> None:
        """Update configuration from typer flags.

        Put this in `typer.callback`."""
        super().callback(output, columns)
        if profile is not None:
            self.config.use.profile = profile
        if self.config.profile is None:
            CONSOLE.print(f"Missing configuration for host `{profile}`.")
            raise typer.Exit(1)

        if host is not None:
            self.config.use.host = host
        if self.config.host is None:
            CONSOLE.print(f"Missing configuration for host `{profile}`.")
            raise typer.Exit(1)

        if self.handler is None:
            raise ValueError("Handler missing.")


__all__ = (
    "UserRequests",
    "CollectionRequests",
    "DocumentRequests",
    # "GrantRequests",
    # "AssignmentRequests",
    "EventsRequests",
    "RequestsEnum",
    "Requests",
)
