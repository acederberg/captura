import enum
from typing import Annotated, List, Optional, Tuple

import httpx
import typer
from client import flags
from client.flags import Output
from client.handlers import CONSOLE

from .assignments import AssignmentRequests
# from .assignments import AssignmentRequests
from .base import BaseRequests, ContextData, params
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


class Requests(BaseRequests):
    typer_check_verbage = False
    typer_commands = dict(routes="req_routes", openapi="req_openapijson")
    typer_children = dict(
        assignments=AssignmentRequests,
        collections=CollectionRequests,
        documents=DocumentRequests,
        grants=GrantRequests,
        users=UserRequests,
        tokens=TokenRequests,
    )

    assignments: AssignmentRequests
    collections: CollectionRequests
    documents: DocumentRequests
    grants: GrantRequests
    users: UserRequests
    tokens: TokenRequests

    def __init__(self, context: ContextData, client: httpx.AsyncClient):
        super().__init__(context, client)
        self.assignents = AssignmentRequests.spawn_from(self)
        self.collections = CollectionRequests.spawn_from(self)
        self.docuents = DocumentRequests.spawn_from(self)
        self.grants = GrantRequests.spawn_from(self)
        self.users = UserRequests.spawn_from(self)
        self.tokens = TokenRequests.spawn_from(self)

    @classmethod
    def req_routes(
        cls,
        _context: typer.Context,
        *,
        methods: Annotated[List[str] | None, typer.Option()] = None,
        names: Annotated[List[str] | None, typer.Option()] = None,
        names_fragment: Annotated[Optional[str], typer.Option] = None,
        paths_fragment: Annotated[Optional[str], typer.Option] = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url("/routes"),
            params=params(
                methods=methods,
                names=names,
                names_fragment=names_fragment,
                paths_fragment=paths_fragment,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_openapijson(
        cls,
        _context: typer.Context,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        res = context.req_openapijson()
        return res


__all__ = (
    "UserRequests",
    "CollectionRequests",
    "DocumentRequests",
    "GrantRequests",
    "AssignmentRequests",
    "EventsRequests",
    "RequestsEnum",
    "BaseRequests",
    "Requests",
)
