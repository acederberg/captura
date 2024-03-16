from typing import Annotated, List, Optional

import httpx
import typer

from client import flags
# from client.apply import ApplyMixins, ApplyMode, ApplyState, apply
from client.config import Config
from client.handlers import Output
from client.requests.assignments import AssignmentRequests
from client.requests.base import BaseRequest, ContextData, params
from client.requests.collections import CollectionRequests
from client.requests.documents import DocumentRequests
from client.requests.grants import GrantRequests
from client.requests.tokens import TokenRequests
from client.requests.users import UserRequests


class It(BaseRequest):

    typer_check_verbage = False
    typer_commands = dict(req_routes="routes")
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
    def routes(
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

    # def callback(
    #     self,
    #     output: flags.FlagOutput = Output.table,
    #     columns: flags.FlagColumns = list(),
    #     *,
    #     profile: flags.FlagProfile = None,
    #     host: flags.FlagHost = None,
    # ) -> None:
    #     super().callback(output, columns, profile=profile, host=host)
    #     assert self.handler is not None
    #     self.handler.column_configs = {
    #         "path": {"justify": "left", "style": typer.colors.CYAN},
    #         "methods": {"justify": "left", "style": typer.colors.BRIGHT_CYAN},
    #         "name": {"justify": "left", "style": typer.colors.CYAN},
    #     }
    #     self.handler.columns = ("path", "methods", "name", )
    # self._state = ApplyState(
    #     handler=self.handler,
    #     mode=ApplyMode.apply,
    #     requests=self,
    # )

    # def apply(
    #     self, filepath: flags.ArgFilePath, mode: ApplyMode = ApplyMode.read
    # ) -> None:
    #
    #     self.state.mode = mode
    #     apply(self, self.state, filepath)


# def test_it():
#     import inspect
#
#     # Inspect callback.
#     sig = inspect.signature(It.callback)
#     assert sig.return_annotation is None
#
#     assert It.commands == ("read", "apply", "destroy")
#     assert (output := sig.parameters.get("output")) is not None
#     assert (columns := sig.parameters.get("columns")) is not None
#     assert (profile := sig.parameters.get("profile")) is not None
#     assert (host := sig.parameters.get("host")) is not None
#
#
# test_it()
#


def main():
    from client.requests.base import typerize

    it = typerize(It)
    it()
    it()
