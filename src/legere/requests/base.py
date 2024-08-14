# =========================================================================== #
import asyncio
import functools
from collections.abc import Awaitable
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Concatenate,
    Dict,
    Generator,
    ParamSpec,
    Self,
    Tuple,
    Type,
    TypeVar,
)
from urllib import parse

import httpx
import typer
import yaml
from click.core import Context as ClickContext
from fastapi.openapi.models import OpenAPI, PathItem
from pydantic import BaseModel, ConfigDict, SecretStr, computed_field
from rich.table import Table
from typer.cli import Command
from typing_extensions import Doc

# --------------------------------------------------------------------------- #
from captura.fields import Singular
from captura.schemas import mwargs
from legere import flags
from legere.config import Config
from legere.flags import Verbage
from legere.handlers import (
    CONSOLE,
    AssertionHandler,
    ConsoleHandler,
    RequestHandlerData,
    render_request,
)

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
        for_method = for_path.get(httpmethod.lower)  # type: ignore
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
    model_config = ConfigDict(arbitrary_types_allowed=True)
    config: Config
    console_handler: ConsoleHandler

    # NOTE: These flags will change how wrapped functions work.
    openapi: flags.FlagOpenApi = False
    show_request: flags.FlagShowRequest = False
    auth_exclude: flags.FlagNoAuthorization = False
    token_from_global: SecretStr | None = None

    def openapijson(self, client: httpx.Client) -> OpenAPI:
        res = client.send(self.req_openapijson())
        return OpenAPI.model_validate(res.json())

    def req_openapijson(self) -> httpx.Request:
        res = httpx.Request(
            "GET",
            url=self.url("/openapi.json"),
        )
        return res

    @computed_field  # type: ignore[prop-decorator]
    @property
    def token(self) -> SecretStr | None:
        return self.token_from_global or self.config.token

    @computed_field  # type: ignore[prop-decorator]
    @property
    def headers(self) -> Dict[str, str]:
        h = dict(content_type="application/json")
        if not self.auth_exclude and (token := self.token) is not None:
            h.update(authorization=f"bearer {token.get_secret_value()}")
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

    def get_config(self, config_path: str | None = None) -> Config:
        """When provided an additional ``config_path``, use said config
        instead. This is included since some commands overwrite the global
        ``--config`` flag.
        """
        if config_path is not None:
            config = Config.load(config_path)
        else:
            config = self.config

        return config

    def url(self, rest: str) -> str:
        if not self.config.host:
            raise ValueError("Host missing.")

        return parse.urljoin(self.config.host.host, rest)

    @classmethod
    def for_typer(
        cls,
        context: typer.Context,
        # Config general,
        path_config: flags.FlagConfig = None,
        profile: flags.FlagProfile = None,
        host: flags.FlagHost = None,
        token: flags.FlagTokenOptional = None,
        # For output
        output: flags.FlagOutput | None = None,
        decorate: flags.FlagDecorate = None,
        # For rest.
        openapi: flags.FlagOpenApi = False,
        show_request: flags.FlagShowRequest = False,
        auth_exclude: flags.FlagNoAuthorization = False,
    ):
        if path_config is None:
            config = mwargs(Config)
        else:
            with open(path_config, "r") as file:
                config = Config.model_validate(yaml.safe_load(file))

        assert config is not None

        if host is not None:
            config.use.host = host
        if profile is not None:
            config.use.profile = profile

        if output is not None:
            # TODO: Figure out why this type hint problem occurs.
            config.output.output = output  # type: ignore
        if decorate is not None:
            config.output.decorate = decorate

        console_handler = ConsoleHandler(config=config)
        context.obj = mwargs(
            ContextData,
            config=config,
            console_handler=console_handler,
            show_request=show_request,
            auth_exclude=auth_exclude,
            token_from_global=token,
        )
        context.obj.openapi = openapi


# =========================================================================== #
# Decorators


P_Wrapped = ParamSpec("P_Wrapped")

MkRequest = Callable[Concatenate[typer.Context | ContextData, P_Wrapped], httpx.Request]
MkRequestTyperized = Callable[Concatenate[typer.Context, P_Wrapped], httpx.Response]


T_Wrapped = TypeVar("T_Wrapped", bound="BaseRequests")
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


# NOTE: This decorator is an abomination. The problem is that we want to
#       convert a classmethod into an instance method.
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

        if self.handler_methodize:
            self.handler(res, **self.create_handler_args())
        return res

    return wrapper


# --------------------------------------------------------------------------- #
# Typer Stuff


def typerize_fn_httx(
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
            request: httpx.Request = fn(_context, *args, **kwargs)
            if context.openapi:
                res = openapi_find(context.openapijson(client), request)
                status = context.console_handler.handle(None, data=res)
                raise typer.Exit(status)

            if context.show_request:
                context.console_handler.console.print(
                    render_request(context.config.output, request)
                )
                raise typer.Exit(1)

            response = client.send(request)

        context.console_handler.handle(response)
        return response

    return wrapper


def typerize(
    cls: Type["BaseTyperizable"],
    *,
    exclude_callback: bool = False,
    callback=None,
    typerize_fn=typerize_fn_httx,
) -> typer.Typer:

    callback = ContextData.for_typer if callback is None else callback
    callback = callback if not exclude_callback else None

    tt = typer.Typer(help=cls.typer_help or cls.__doc__)
    if not exclude_callback:
        assert callback is not None
        tt.callback()(callback)

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
        tt.add_typer(
            typerize(group_cls, callback=callback, exclude_callback=True),
            name=group_name,
        )

    return tt


# =========================================================================== #
# BaseRequests


class BaseTyperizable:
    typer_help: ClassVar[str | None] = None
    typer_decorate: ClassVar[bool] = True
    typer_check_verbage: ClassVar[bool] = True
    typer_commands: ClassVar[Dict[str, str]] = dict()
    typer_children: ClassVar[Dict[str, Type["BaseTyperizable"]]] = dict()

    def render_table(self) -> Table | None: ...


class BaseRequests(BaseTyperizable):

    context: ContextData
    client: httpx.AsyncClient
    handler: AssertionHandler
    handler_methodize: Annotated[
        bool,
        Doc(
            "When ``True``, methodized functions will use this callback. "
            "The attached handler will be ignored."
        ),
    ]

    def __init__(
        self,
        context: ContextData,
        client: httpx.AsyncClient,
        *,
        handler: AssertionHandler | None = None,
        handler_methodize: bool = False,
    ):
        self.context = context
        self.client = client
        self.handler = handler or AssertionHandler(context.config)
        self.handler_methodize = handler_methodize

    @functools.cached_property
    def context_wrapped(self) -> typer.Context:
        return typer.Context(Command("empty"), obj=self.context)

    @classmethod
    def spawn_from(cls, v: "BaseRequests") -> Self:
        "Make an instance from existing instance."
        return cls(
            context=v.context,
            client=v.client,
            handler=v.handler,
            handler_methodize=v.handler_methodize,
        )

    async def gather(
        self, *items: httpx.Request, **handler_kwargs
    ) -> Tuple[RequestHandlerData, ...]:
        responses = await asyncio.gather(*map(self.client.send, items))
        return self.handler(responses, **handler_kwargs)

    async def send(
        self, request: httpx.Request, **handler_kwargs
    ) -> RequestHandlerData:
        response = await self.client.send(request)
        return self.handler(response, **handler_kwargs)[0]

    def create_handler_args(self) -> Dict[str, Any]:
        return dict()


def params(**kwargs) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}
