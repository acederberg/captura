import functools
import asyncio
from app.views import AppView

import httpx
from typing import (
    Dict,
    ClassVar,
    Type,
    TypeVar,
    Awaitable,
    ParamSpec,
    Callable,
    Any,
    Concatenate,
    Tuple,
)
from typing_extensions import Self

import typer


from client import flags
from client.flags import Output, Verbage
from client.config import Config
from client.handlers import ConsoleHandler, Handler


# =========================================================================== #
# TYPES

V = ParamSpec("V")
S = TypeVar("S")
RequestMethod = Callable[Concatenate[S, V], Awaitable[httpx.Response]]


def try_handler(meth: RequestMethod) -> RequestMethod:
    @functools.wraps(meth)
    async def wrapper(
        self,
        *args: V.args,
        **kwargs: V.kwargs,
    ) -> httpx.Response:
        res = await meth(self, *args, **kwargs)
        if self.handler:
            handler: Handler = self.handler
            return await handler(res)
        return res

    return wrapper


def params(**kwargs) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


# =========================================================================== #


class RequestMixins:
    # CLASSVAR DEFAULTS ARE IN META AS ATTRS
    command: ClassVar[str] = "base"
    commands: ClassVar[Tuple[str, ...]] = tuple()
    children: ClassVar[Tuple["RequestMeta", ...]] = tuple()

    children_instances: Dict[str, "BaseRequest"]
    config: Config
    handler: Handler | None

    # Exposed as properties
    _token: str | None
    _client: httpx.AsyncClient | None

    # NOTE: Handler should only be passed for non cli purposes (i.e. in pytest
    #       fixtures). In the case of typer, the callback will create a
    #       `ConsoleHandler` for the instance.
    def __init__(
        self,
        config: Config,
        client: httpx.AsyncClient | None = None,
        token: str | None = None,
        *,
        children_instances: Dict[str, "BaseRequest"] = dict(),
        handler: Handler | None = None,
    ):
        self.config = config
        self._client = client

        self.children_instances = children_instances
        self._token = token
        self.handler = handler

    @classmethod
    def from_(cls, v: "BaseRequest") -> Self:
        "Make an instance from existing instance."
        return cls(
            handler=v.handler,
            client=v._client,
            config=v.config,
            token=v._token,
        )


class RequestMeta(type):
    # NOTE: Should match classvars on `RequestMixins`.
    command: str
    commands: Tuple[str, ...]
    children: Tuple["RequestMeta", ...]

    def __new__(cls, name: str, bases, namespace):
        # NOTE: Construct T first so that commands from inherited fns
        #       can be found and so that commands from bases may be included.
        if RequestMixins not in bases:
            bases = (*bases, RequestMixins)

        T = super().__new__(cls, name, bases, namespace)
        T.commands += tuple(
            command
            for base in bases
            if isinstance(commands := getattr(base, "commands", None), tuple)
            for command in commands
        )

        command, commands = T.command, T.commands
        if command is None:
            raise ValueError(f"Missing command for `{name}`.")

        acceptable = Verbage._value2member_map_
        if commands is None:
            raise AttributeError(f"`{name}` missing `commands`.")
        elif len(bad := list(cc for cc in commands if cc not in acceptable)):
            msg = f"`{name}.commands` contains illegal verbage `{bad}`."
            raise AttributeError(msg)
        elif len(bad := [cc for cc in commands if not hasattr(T, cc)]):
            raise AttributeError(f"`{name}` missing commands `{bad}`.")

        # NOTE: Decorate commands. Should be done after type construction
        #       because all commands will not exist in `namespace`.
        for cc in commands:
            fn = getattr(T, cc)
            fn_with_handler = try_handler(fn)
            setattr(T, cc, fn_with_handler)

        return T


class BaseRequest(RequestMixins, metaclass=RequestMeta):
    @functools.cached_property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            msg = "Client has was not provided to constructor or set."
            raise ValueError(msg)
        return self._client

    def typerize(
        self, fn: Callable[Concatenate[V], Awaitable[httpx.Response]]
    ) -> Callable[Concatenate[V], httpx.Response]:
        """Add client and self. Make sync."""

        async def wrapper(*args: V.args, **kwargs: V.kwargs):
            app = None
            if not self.config.host.remote:
                app = AppView.view_router
            async with httpx.AsyncClient(
                base_url=self.config.host.host, app=app
            ) as client:
                self.client = client
                res = await fn(*args, **kwargs)
            return res

        # Typer will not run async.
        @functools.wraps(fn)
        def wrappersync(
            *args: V.args,
            **kwargs: V.kwargs,
        ) -> httpx.Response:
            res = asyncio.run(wrapper(*args, **kwargs))
            return res

        return wrappersync

    @functools.cached_property
    def typer(self) -> typer.Typer:
        # Necessary are the function from `fns` must be bound.
        t: typer.Typer = typer.Typer(callback=self.callback)
        for command in self.commands:
            command_clean = command.replace("_", "-")
            decorator = t.command(command_clean)
            cmd_again = self.typerize(getattr(self, command))
            decorator(cmd_again)

        if not self.children_instances:
            self.children_instances = {
                child.command: child.from_(self) for child in self.children
            }

        for name, requester in self.children_instances.items():
            t.add_typer(requester.typer, name=name)

        return t

    @property
    def token(self):
        if self._token is not None:
            return self._token
        return self.config.profile.token

    @property
    def headers(self):
        h = dict(content_type="application/json")
        if self.token:
            h.update(authorization=f"bearer {self.token}")
        return h

    def callback(
        self,
        output: flags.FlagOutput = Output.json,
        columns: flags.FlagColumns = list(),
    ):
        """Specify request output format."""
        self.handler = ConsoleHandler(output=output, columns=columns)


__all__ = (
    "RequestMethod",
    "try_handler",
    "params",
    "RequestMeta",
    "BaseRequest",
)
