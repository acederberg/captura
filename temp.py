import abc
from collections.abc import Awaitable
from typing import (Annotated, Any, Awaitable, Callable, ClassVar, Concatenate,
                    Dict, Generic, ParamSpec, Protocol, Self, Set, Tuple, Type,
                    TypeAlias, TypeVar)

import httpx
import rich
import typer
from pydantic import BaseModel, computed_field

from app.schemas import mwargs
from client.config import Config, UseConfig, flags
from client.flags import Output
from client.handlers import ConsoleHandler, Handler

# --------------------------------------------------------------------------- #

class ContextData(BaseModel):
    config: Config
    console_handler: ConsoleHandler

    @computed_field
    @property
    def headers(self) -> Dict[str, str]:
        h = dict(content_type="application/json")
        if self.config.token is not None:
            h.update(authorization=f"bearer {self.config.token}")
        return h

    @classmethod
    def resolve(cls, ctx: typer.Context) -> Self:
        if ctx.obj is None:
            raise ValueError("Context missing `object`.")
            # ctx.obj = cls.model_validate(
            #     ctx.obj["config"],
            # )
        return ctx.obj

    def url(self, *rest: str) -> str:
        if not self.config.host:
            raise ValueError("Host missing.")

        return "/".join((self.config.host.host, *rest))


class Base:
    typer_commands: ClassVar[Set[str]]
    typer_command: ClassVar[str]
    typer_children: ClassVar[Tuple[Type["Base"], ...]]


class User(Base):

    @classmethod
    def read(
        cls,
        _context: typer.Context,
        uuid: flags.ArgUUIDUser,
    ) -> httpx.Request:

        # context = ContextData.resolve(_context)
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            url=context.url(f"/users/{uuid}"),
            headers=context.headers,
        )

    typer_commands = {"read"}
    typer_children = tuple()
    typer_command = "user"


def create_context(
    context: typer.Context,
    profile: flags.FlagProfile = None,
    host: flags.FlagHost = None,
    output: flags.FlagOutput = Output.json,
    columns: flags.FlagColumns = list(),
):
    config = mwargs(Config)
    if host is not None:
        config.use.host = host
    if profile is not None:
        config.use.profile = profile

    console_handler = mwargs(ConsoleHandler, output=output, columns=columns)
    context.obj = ContextData(config=config, console_handler=console_handler)


# --------------------------------------------------------------------------- #

P_Wrapped = ParamSpec("P_Wrapped")
T_Wrapped = TypeVar("T_Wrapped", bound=Type["Base"])

MkRequest = Callable[Concatenate[typer.Context, P_Wrapped], httpx.Request]
MkRequestTyperized = Callable[
    Concatenate[typer.Context, P_Wrapped], httpx.Response
]


import functools


def typerize_fn(
    fn: MkRequest[ P_Wrapped]
) -> MkRequestTyperized[ P_Wrapped]:

    @functools.wraps(fn)
    def wrapper(
        # cls: T_Wrapped,
        _context: typer.Context,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:

        context = ContextData.resolve(_context)
        if (host := context.config.host) is None:
            rich.print("Missing host.")
            raise typer.Exit(1)

        with httpx.Client(base_url=host.host, headers=context.headers) as client:
            request = fn(_context, *args, **kwargs)
            response = client.send(request)

        context.console_handler.handle(response)
        return response

    return wrapper


def typerize(cls: Type[Base]) -> typer.Typer:

    tt = typer.Typer(
        callback=create_context,
        # context_settings=
    )

    print(cls)
    for command_name in cls.typer_commands:
        if (command_fn := getattr(cls, command_name, None)) is None:
            raise ValueError(f"No function `{command_name}`.")

        tt.command(command_name)(typerize_fn(command_fn))

    return tt


tt = typerize(User)
tt()
