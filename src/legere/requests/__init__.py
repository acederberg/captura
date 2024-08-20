# =========================================================================== #
import enum
from typing import Annotated, List, Optional

import httpx
import typer

# --------------------------------------------------------------------------- #
from legere.handlers import AssertionHandler

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

    def __init__(
        self,
        context: ContextData,
        client: httpx.AsyncClient,
        *,
        handler: AssertionHandler | None = None,
        handler_methodize: bool = False,
    ):
        super().__init__(
            context,
            client,
            handler=handler,
            handler_methodize=handler_methodize,
        )
        self.assignments = AssignmentRequests.spawn_from(self)
        self.collections = CollectionRequests.spawn_from(self)
        self.documents = DocumentRequests.spawn_from(self)
        self.grants = GrantRequests.spawn_from(self)
        self.users = UserRequests.spawn_from(self)
        self.tokens = TokenRequests.spawn_from(self)

    @property
    def a(self) -> AssignmentRequests:
        return self.assignments

    @property
    def c(self) -> CollectionRequests:
        return self.collections

    @property
    def d(self) -> DocumentRequests:
        return self.documents

    @property
    def g(self) -> GrantRequests:
        return self.grants

    @property
    def u(self) -> UserRequests:
        return self.users

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
