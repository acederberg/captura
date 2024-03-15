import abc
import functools
from collections.abc import Awaitable
from typing import (Annotated, Any, Awaitable, Callable, ClassVar, Concatenate,
                    Dict, Generic, ParamSpec, Protocol, Self, Set, Tuple, Type,
                    TypeAlias, TypeVar)

import httpx
import rich
import typer
from click.core import Context as ClickContext
from pydantic import BaseModel, computed_field

from app.schemas import mwargs
from client.config import Config, UseConfig, flags
from client.flags import Output, Verbage
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
    def resolve(cls, ctx: typer.Context | Self) -> Self:
        match ctx:
            case ClickContext():
                if ctx.obj is None:
                    raise ValueError("Context missing `object`.")
                    # ctx.obj = cls.model_validate(
                    #     ctx.obj["config"],
                    # )
                return ctx.obj
            case cls(): # type: ignore
                return ctx
            case bad:
                raise ValueError(f"Cannot resolve context from `{bad}`.")

    def url(self, *rest: str) -> str:
        if not self.config.host:
            raise ValueError("Host missing.")

        return "/".join((self.config.host.host, *rest))


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





P_Wrapped = ParamSpec("P_Wrapped")

MkRequest = Callable[Concatenate[typer.Context | ContextData, P_Wrapped], httpx.Request]
MkRequestTyperized = Callable[
    Concatenate[typer.Context, P_Wrapped], httpx.Response
]


T_Wrapped = TypeVar("T_Wrapped", bound="Base")
MkRequestCls = Callable[
    Concatenate[Type[T_Wrapped], typer.Context | ContextData, P_Wrapped], httpx.Request] |Callable[Concatenate[Type[T_Wrapped], typer.Context, P_Wrapped], httpx.Request] 
MkRequestInstance = Callable[
    Concatenate[T_Wrapped, P_Wrapped], Awaitable[httpx.Response]
]


def methodize(
    fn: MkRequestCls[T_Wrapped, P_Wrapped],
    __func__: Callable | None = None,
) -> MkRequestInstance[T_Wrapped, P_Wrapped]:
    if __func__ is not None:
        fn = __func__

    @functools.wraps(fn)
    async def wrapper(
        self: T_Wrapped,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:

        req = fn(self.__class__, self.context, *args, **kwargs)
        res = await self.client.send(req)
        return res

    return wrapper


def typerize_fn(
    fn: MkRequest[P_Wrapped],
) -> MkRequestTyperized[P_Wrapped]:

    @functools.wraps(fn)
    def wrapper(
        _context: typer.Context,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:

        context = ContextData.resolve(_context)
        with httpx.Client() as client:
            request = fn(_context, *args, **kwargs)
            response = client.send(request)

        context.console_handler.handle(response)
        return response

    return wrapper


def typerize(cls: Type["Base"]) -> typer.Typer:

    tt = typer.Typer(
        callback=create_context,
        # context_settings=
    )

    for command_name, command_name_fn in cls.typer_commands.items():
        if cls.typer_check_verbage:
            if command_name not in Verbage._member_map_:
                raise ValueError(f"Illegal verbage `{command_name}`.")

        if (command_fn := getattr(cls, command_name_fn, None)) is None:
            raise ValueError(f"No function `{command_name_fn}`.")

        tt.command(command_name)(typerize_fn(command_fn))
    
    for group_name, group_cls in cls.typer_children.items():
        tt.add_typer(typerize(group_cls), name=group_name)

    return tt


# --------------------------------------------------------------------------- #

class Base:
    typer_check_verbage: ClassVar[bool] = True
    typer_commands: ClassVar[Dict[str, str]] = dict()
    typer_children: ClassVar[Dict[str, Type["Base"]]] = dict()

    context: ContextData
    client: httpx.AsyncClient

    def __init__(
        self,
        context: ContextData,
        client: httpx.AsyncClient,
    ):
        self.context = context
        self.client = client

    @classmethod
    def spawn_from(cls, v: "Base") -> Self:
        "Make an instance from existing instance."
        return cls(
            context=v.context,
            client=v.client,
        )


class User(Base):

    @classmethod
    def req_read(
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

    children = tuple()
    typer_commands = {"read": "req_read"}

    read = methodize(req_read, __func__=req_read.__func__)


class Cli(Base):

    typer_children = {"users": User}

    users: User

    def __init__(self, context: ContextData, client: httpx.AsyncClient):
        super().__init__(context, client)
        self.users = User.spawn_from(self)



async def main():

    context = ContextData(config=Config(), console_handler=mwargs(ConsoleHandler))
    async with httpx.AsyncClient() as client:

        u = Cli(context=context, client=client)
        res = await u.users.read("000-000-000")
        print("HERE", res)

import asyncio

asyncio.run(main())


cli = typerize(Cli)
cli()


