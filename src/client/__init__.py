import typer

# --------------------------------------------------------------------------- #
from client.config import Config
from client.handlers import CONSOLE, ConsoleHandler
from client.requests import Requests
from client.requests.assignments import AssignmentRequests
from client.requests.base import BaseRequests, BaseTyperizable, ContextData, params
from client.requests.collections import CollectionRequests
from client.requests.documents import DocumentRequests
from client.requests.grants import GrantRequests
from client.requests.tokens import TokenRequests
from client.requests.users import UserRequests


class ConfigCommands(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(profiles="profiles", hosts="hosts", show="show")
    typer_children = dict()

    @classmethod
    def profiles(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        profiles = context.config.profiles
        context.console_handler.handle(
            data={pp: qq.model_dump(mode="json") for pp, qq in profiles.items()}
        )

        return

    @classmethod
    def hosts(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        hosts = context.config.hosts
        context.console_handler.handle(
            data={pp: qq.model_dump(mode="json") for pp, qq in hosts.items()}
        )

        return

    @classmethod
    def show(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)
        config = context.config
        profile = (
            None if config.profile is None else config.profile.model_dump(mode="json")
        )
        host = None if config.host is None else config.host.model_dump(mode="json")
        data = {config.use.profile: profile, config.use.host: host}
        context.console_handler.handle(data=data)


__all__ = (
    "AssignmentRequests",
    "BaseRequests",
    "ContextData",
    "params",
    "CollectionRequests",
    "DocumentRequests",
    "GrantRequests",
    "TokenRequests",
    "UserRequests",
    "ConsoleHandler",
    "CONSOLE",
    "Requests",
    "Config",
)
