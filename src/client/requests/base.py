import functools
from collections.abc import Awaitable
from typing import (Any, Awaitable, Callable, ClassVar, Concatenate, Dict,
                    ParamSpec, Self, Type, TypeVar)
from urllib import parse

import httpx
import typer
from app.schemas import mwargs
from click.core import Context as ClickContext
from client.config import Config, flags
from client.flags import Output, Verbage
from client.handlers import ConsoleHandler
from pydantic import BaseModel, computed_field

# =========================================================================== #
# Data for `ClickContext`.


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
                return ctx.obj
            case cls(): # type: ignore
                return ctx
            case bad:
                raise ValueError(f"Cannot resolve context from `{bad}`.")

    def url(self, rest: str) -> str:
        if not self.config.host:
            raise ValueError("Host missing.")

        return parse.urljoin(self.config.host.host, rest)


# =========================================================================== #
# Decorators


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
        fn = __func__ # type: ignore

    @functools.wraps(fn)
    async def wrapper(
        self: T_Wrapped,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:

        # The type hint cannot include `ContextData | typer.Context` bc typer.
        req = fn(self.__class__, self.context, *args, **kwargs) # type: ignore
        res = await self.client.send(req)
        return res

    return wrapper


# --------------------------------------------------------------------------- #
# Typer Stuff


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


# =========================================================================== #
# BaseRequests

class BaseRequests:
    typer_check_verbage: ClassVar[bool] = True
    typer_commands: ClassVar[Dict[str, str]] = dict()
    typer_children: ClassVar[Dict[str, Type["BaseRequests"]]] = dict()

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
    def spawn_from(cls, v: "BaseRequests") -> Self:
        "Make an instance from existing instance."
        return cls(
            context=v.context,
            client=v.client,
        )

def params(**kwargs) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}
