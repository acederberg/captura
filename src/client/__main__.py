from typing import Annotated, List, Optional

import httpx
import typer

from client.requests.assignments import AssignmentRequests
from client.requests.base import BaseRequests, ContextData, params
from client.requests.collections import CollectionRequests
from client.requests.documents import DocumentRequests
from client.requests.grants import GrantRequests
from client.requests.tokens import TokenRequests
from client.requests.users import UserRequests


class Config:
    @classmethod
    def profiles(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        profiles = context.config.profiles
        context.console_handler.handle(data={
            pp: qq.model_dump(mode="json") for pp, qq in profiles.items()})

        return

    @classmethod
    def hosts(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        hosts = context.config.hosts
        context.console_handler.handle(data={
            pp: qq.model_dump(mode="json") for pp, qq in hosts.items()})

        return

    @classmethod
    def show(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)
        config = context.config
        profile = None if config.profile is None else config.profile.model_dump(mode="json")
        host =  None if config.host is None else config.host.model_dump(mode="json") 
        data = {config.use.profile: profile, config.use.host: host}
        context.console_handler.handle(data=data)

    @classmethod
    def typer(cls) -> typer.Typer:
        cli = typer.Typer()
        cli.command("profiles")(cls.profiles)
        cli.command("hosts")(cls.hosts)
        cli.command("show")(cls.show)
        return cli


class It(BaseRequests):

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
    it.add_typer(Config.typer(), name="config")
    it()
