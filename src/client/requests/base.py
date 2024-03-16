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
# BaseRequest

class BaseRequest:
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

def params(**kwargs) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}

# =========================================================================== #
# EXAMPLE 
#
# class User(Base):
#
#     @classmethod
#     def req_read(
#         cls,
#         _context: typer.Context,
#         uuid: flags.ArgUUIDUser,
#     ) -> httpx.Request:
#
#         # context = ContextData.resolve(_context)
#         context = ContextData.resolve(_context)
#         return httpx.Request(
#             "GET",
#             url=context.url(f"/users/{uuid}"),
#             headers=context.headers,
#         )
#
#     children = tuple()
#     typer_commands = {"read": "req_read"}
#
#     read = methodize(req_read, __func__=req_read.__func__)
#
#
# class Cli(Base):
#
#     typer_children = {"users": User}
#
#     users: User
#
#     def __init__(self, context: ContextData, client: httpx.AsyncClient):
#         super().__init__(context, client)
#         self.users = User.spawn_from(self)
#
#
#
# async def main():
#
#     context = ContextData(config=Config(), console_handler=mwargs(ConsoleHandler))
#     async with httpx.AsyncClient() as client:
#
#         u = Cli(context=context, client=client)
#         res = await u.users.read("000-000-000")
#         print("HERE", res)
#
# import asyncio
#
# asyncio.run(main())
#
#
# cli = typerize(Cli)
# cli()
# =========================================================================== #



# # =========================================================================== #
# # TYPES
#
# V = ParamSpec("V")
# S = TypeVar("S")
# RequestMethod = Callable[Concatenate[S, V], Awaitable[httpx.Response]]
#
#
# def try_handler(meth: RequestMethod) -> RequestMethod:
#     @functools.wraps(meth)
#     async def wrapper(
#         self,
#         *args: V.args,
#         **kwargs: V.kwargs,
#     ) -> httpx.Response:
#         res = await meth(self, *args, **kwargs)
#         if self.handler:
#             handler: Handler = self.handler
#             return await handler(res)
#         return res
#
#     return wrapper
#
#
#
#
# # =========================================================================== #
#
#
# class RequestMixins:
#     # CLASSVAR DEFAULTS ARE IN META AS ATTRS
#     command: ClassVar[str] = "base"
#     commands_check_verbage: ClassVar[bool] = True
#     commands: ClassVar[Tuple[str, ...]] = tuple()
#     children: ClassVar[Tuple["RequestMeta", ...]] = tuple()
#
#     children_instances: Dict[str, "BaseRequest"]
#     config: Config
#     handler: Handler | None
#
#     # Exposed as properties
#     _token: str | None
#     _client: httpx.AsyncClient | None
#
#     # NOTE: Handler should only be passed for non cli purposes (i.e. in pytest
#     #       fixtures). In the case of typer, the callback will create a
#     #       `ConsoleHandler` for the instance.
#     def __init__(
#         self,
#         config: Config,
#         client: httpx.AsyncClient | None = None,
#         token: str | None = None,
#         *,
#         children_instances: Dict[str, "BaseRequest"] = dict(),
#         handler: Handler | None = None,
#     ):
#         self.config = config
#         self._client = None
#         if client is not None:
#             self.client = client
#
#         self.children_instances = children_instances
#         self._token = token
#         self.handler = handler
#
#     @classmethod
#     def from_(cls, v: "BaseRequest") -> Self:
#         "Make an instance from existing instance."
#         return cls(
#             handler=v.handler,
#             client=v._client,
#             config=v.config,
#             token=v._token,
#         )
#
#
# class RequestMeta(type):
#     # NOTE: Should match classvars on `RequestMixins`.
#     command: str
#     commands: Tuple[str, ...]
#     commands_check_verbage: bool
#     children: Tuple["RequestMeta", ...]
#
#     def __new__(cls, name: str, bases, namespace):
#         # NOTE: Construct T first so that commands from inherited fns
#         #       can be found and so that commands from bases may be included.
#         if RequestMixins not in bases:
#             bases = (*bases, RequestMixins)
#
#         T = super().__new__(cls, name, bases, namespace)
#         T.commands += tuple(
#             command
#             for base in bases
#             if isinstance(commands := getattr(base, "commands", None), tuple)
#             for command in commands
#         )
#
#     @classmethod
#     def check_attrs(cls, T):
#         name = T.__name__
#         command, commands = T.command, T.commands
#         if command is None:
#             raise ValueError(f"Missing command for `{name}`.")
#
#         acceptable = Verbage._value2member_map_
#         if commands is None:
#             raise AttributeError(f"`{name}` missing `commands`.")
#         elif T.commands_check_verbage and len(bad := list(cc for cc in commands if cc not in acceptable)):
#             msg = f"`{name}.commands` contains illegal verbage `{bad}`."
#             raise AttributeError(msg)
#         elif len(bad := [cc for cc in commands if not hasattr(T, cc)]):
#             raise AttributeError(f"`{name}` missing commands `{bad}`.")
#
#         # NOTE: Decorate commands. Should be done after type construction
#         #       because all commands will not exist in `namespace`.
#         for cc in commands:
#             fn = getattr(T, cc)
#             fn_with_handler = try_handler(fn)
#             setattr(T, cc, fn_with_handler)
#
#         return T
#
#
# class BaseRequest(RequestMixins, metaclass=RequestMeta):
#     @property
#     def client(self) -> httpx.AsyncClient:
#         if self._client is None:
#             msg = "Client has was not provided to constructor or set."
#             raise ValueError(msg)
#         return self._client
#
#     @client.setter
#     def client(self, v: httpx.AsyncClient):
#         # CONSOLE.print(
#         #     f"[red]Setting client `{self}@{self.__class__.__name__}` with "
#         #     "value `{v}`."
#         # )
#         self._client = v
#         # CONSOLE.print(f"[orange]{self.client}")
#         for child in self.children_instances.values():
#             child.client = v
#
#     # ----------------------------------------------------------------------- #
#     # Async context.
#     async def __aenter__(self, app, **kwargs):
#         client = httpx.AsyncClient(
#             base_url=self.config.host.host,
#             app=app,
#             **kwargs,
#         )
#         await self.client.__aenter__()
#         self.client = client
#         return
#
#     async def __aexit__(self, exc_type, exc_value, tb):
#         await self.client.__aexit__(exc_type, exc_value, tb)
#
#     @property
#     def token(self):
#         if self._token is not None:
#             return self._token
#         return self.config.profile.token
#
#     @token.setter
#     def token(self, v: Dict[str, str]):
#         self._token = v
#         for item in self.children_instances:
#             item.token = v
#
#     @property
#     def headers(self):
#         h = dict(content_type="application/json")
#         if self.token:
#             h.update(authorization=f"bearer {self.token}")
#         return h
#
#     def typerize(
#         self, fn: Callable[Concatenate[V], Awaitable[httpx.Response]]
#     ) -> Callable[Concatenate[V], httpx.Response]:
#         """Add client and self. Make sync."""
#
#         # CONSOLE.print(f"[orange]Decorating `{fn}`.")
#
#         async def wrapper(*args: V.args, **kwargs: V.kwargs):
#             app = None
#             if not self.config.host.remote:
#                 app = AppView.view_router
#             async with httpx.AsyncClient(
#                 base_url=self.config.host.host, app=app
#             ) as client:
#                 self.client = client
#                 assert self.client
#                 res = await fn(*args, **kwargs)
#             return res
#
#         @functools.wraps(fn)
#         def wrappersync(
#             *args: V.args,
#             **kwargs: V.kwargs,
#         ) -> httpx.Response:
#             res = asyncio.run(wrapper(*args, **kwargs))
#             return res
#
#         return wrappersync
#
#     @functools.cached_property
#     def typer(self) -> typer.Typer:
#         t: typer.Typer = typer.Typer(callback=self.callback)
#         for command in self.commands:
#             command_clean = command.replace("_", "-")
#             decorator = t.command(command_clean)
#             cmd_again = self.typerize(getattr(self, command))
#             decorator(cmd_again)
#
#         if not self.children_instances:
#             self.children_instances = {
#                 child.command: child.from_(self) for child in self.children
#             }
#
#         for name, requester in self.children_instances.items():
#             t.add_typer(requester.typer, name=name)
#
#         return t
#
#     def callback(
#         self,
#         output: flags.FlagOutput = Output.json,
#         columns: flags.FlagColumns = list(),
#     ):
#         """Specify request output format."""
#         self.handler = ConsoleHandler(output=output, columns=columns)
#
#
# __all__ = (
#     "RequestMethod",
#     "try_handler",
#     "params",
#     "RequestMeta",
#     "BaseRequest",
# )
