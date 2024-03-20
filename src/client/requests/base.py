import functools
import json
import urllib
from collections.abc import Awaitable
from os import walk
from typing import (Any, Awaitable, Callable, ClassVar, Concatenate, Dict,
                    Generator, ParamSpec, Self, Type, TypeVar)
from urllib import parse

import httpx
import typer
from app.models import Singular
from app.schemas import mwargs
from click.core import Context as ClickContext
from client import flags
from client.config import Config
from client.flags import Output, Verbage
from client.handlers import CONSOLE, ConsoleHandler
from fastapi.openapi.models import OpenAPI, PathItem
from pydantic import BaseModel, TypeAdapter, computed_field
from rich.console import Console

# =========================================================================== #
# Helpers for decorators.

url_chunks_accepted = {"users", "documents", "collections", "assignments"}
url_chunks_accepted |= {"grants", "extensions", "demos"}


def openapi_match(req: httpx.Request) -> Generator[str, None, None]:
    chunks = req.url.path.split("/")[1:]

    last_chunk = None
    for chunk in chunks:
        if chunk in url_chunks_accepted:
            yield chunk
            last_chunk = chunk
        else:
            if last_chunk is None:
                raise ValueError(
                    f"Last chunk not yet specified (the current chunk is `{chunk}`)."
                )
            elif last_chunk == "uuid":
                raise ValueError(
                    "Cannot determine uuid from last_chunk since it was a "
                    f"uuid (the current chunk is `{chunk}`)."
                )

            if last_chunk == "demos":
                yield "invitation_uuid"
            else:
                yield f"{{uuid_{Singular[last_chunk].value}}}"
                last_chunk = "uuid"


def openapi_find(openapi: OpenAPI, req: httpx.Request) -> PathItem:
    url = req.url
    path = str(url.path)
    assert path is not None
    assert openapi.paths is not None

    fpath = "/" + "/".join(openapi_match(req))
    httpmethod = req.method
    try:
        for_path = openapi.paths[fpath]
        for_method = for_path.get(httpmethod.lower())
        return for_method
    except KeyError as err:
        CONSOLE.print(
            f"[red]Could not find data in OpenAPI schema for "
            f"`{httpmethod} {fpath}`."
        )
        raise typer.Exit(1) from err


# =========================================================================== #
# Data for `ClickContext`.

class ContextData(BaseModel):
    config: Config
    console_handler: ConsoleHandler

    # NOTE: These flags will change how wrapped functions work.
    openapi: flags.FlagOpenApi = False
    show_request: flags.FlagShowRequest = False

    def openapijson(self, client: httpx.Client) -> OpenAPI:
        res = client.send(self.req_openapijson())
        return OpenAPI.model_validate(res.json())

    def req_openapijson(self) -> httpx.Request:
        res = httpx.Request(
            "GET",
            url=self.url("/openapi.json"),
        )
        return res

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
            case cls():  # type: ignore
                return ctx
            case bad:
                raise ValueError(f"Cannot resolve context from `{bad}`.")

    def url(self, rest: str) -> str:
        if not self.config.host:
            raise ValueError("Host missing.")

        return parse.urljoin(self.config.host.host, rest)

    @classmethod
    def for_typer(
        cls,
        context: typer.Context,
        profile: flags.FlagProfile = None,
        host: flags.FlagHost = None,
        output: flags.FlagOutput = Output.json,
        columns: flags.FlagColumns = list(),
        openapi: flags.FlagOpenApi = False,
        show_request: flags.FlagShowRequest = False,
    ):
        config = mwargs(Config)
        if host is not None:
            config.use.host = host
        if profile is not None:
            config.use.profile = profile

        console_handler = mwargs(ConsoleHandler, output=output, columns=columns)
        context.obj = ContextData(
            config=config, console_handler=console_handler, show_request=show_request
        )
        context.obj.openapi = openapi


# =========================================================================== #
# Decorators


P_Wrapped = ParamSpec("P_Wrapped")

MkRequest = Callable[Concatenate[typer.Context | ContextData, P_Wrapped], httpx.Request]
MkRequestTyperized = Callable[Concatenate[typer.Context, P_Wrapped], httpx.Response]


T_Wrapped = TypeVar("T_Wrapped", bound="Base")
MkRequestCls = (
    Callable[
        Concatenate[Type[T_Wrapped], typer.Context | ContextData, P_Wrapped],
        httpx.Request,
    ]
    | Callable[Concatenate[Type[T_Wrapped], typer.Context, P_Wrapped], httpx.Request]
)
MkRequestInstance = Callable[
    Concatenate[T_Wrapped, P_Wrapped], Awaitable[httpx.Response]
]


# --------------------------------------------------------------------------- #
# Test client stuff.

# NOTE: The type hint of fn cannot include `ContextData | typer.Context` bc 
#       typer. ``__func__`` is included because classmethods are processed 
#       after the end of the class definition.
def methodize(
    fn: MkRequestCls[T_Wrapped, P_Wrapped],
    __func__: Callable | None = None,
) -> MkRequestInstance[T_Wrapped, P_Wrapped]:
    if __func__ is not None:
        fn = __func__  # type: ignore

    @functools.wraps(fn)
    async def wrapper(
        self: T_Wrapped,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:
        req = fn(self.__class__, self.context, *args, **kwargs)  # type: ignore
        res = await self.client.send(req)
        return res

    return wrapper


# --------------------------------------------------------------------------- #
# Typer Stuff


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
        console: Console = context.console_handler.console
        with httpx.Client() as client:
            request: httpx.Request = fn(_context, *args, **kwargs)
            if context.openapi:
                res = openapi_find(context.openapijson(client), request)
                context.console_handler.handle(None, data=res)
                raise typer.Exit(0)

            if context.show_request:
                console.print("")
                console.print(f"[bold blue]{request.method} [green]{request.url}")
                console.print("")
                console.print(
                    "\r\n".join(
                        f"[bold blue]{key}[/bold blue][grey]: [green]{value}[/green]".format(key, value)
                        for key, value in request.headers.items()
                    )
                )
                console.print("")
                console.print_json(request.content.decode() or "null")
                console.print("")
                raise typer.Exit(1)

            response = client.send(request)

        context.console_handler.handle(response)
        return response

    return wrapper


def typerize(cls: Type["BaseTyperizable"], *, is_recurse: bool = False) -> typer.Typer:
    tt = typer.Typer(callback=ContextData.for_typer if not is_recurse else None)

    for command_name, command_name_fn in cls.typer_commands.items():
        if cls.typer_check_verbage:
            if command_name not in Verbage._member_map_:
                raise ValueError(f"Illegal verbage `{command_name}`.")

        if (command_fn := getattr(cls, command_name_fn, None)) is None:
            raise ValueError(f"No function `{command_name_fn}`.")

        if cls.typer_decorate:
            command_fn = typerize_fn(command_fn)
        tt.command(command_name)(command_fn)

    for group_name, group_cls in cls.typer_children.items():
        tt.add_typer(typerize(group_cls, is_recurse=True), name=group_name)

    return tt


# =========================================================================== #
# BaseRequests

class BaseTyperizable:
    typer_decorate: ClassVar[bool] = True
    typer_check_verbage: ClassVar[bool] = True
    typer_commands: ClassVar[Dict[str, str]] = dict()
    typer_children: ClassVar[Dict[str, Type["BaseRequests"]]] = dict()


class BaseRequests(BaseTyperizable):
    typer_decorate: ClassVar[bool] = True
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
