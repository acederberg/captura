from typing import ClassVar, Type
import functools
import asyncio

import fastapi
from client import flags
import enum
import httpx
from typing import (
    Awaitable,
    Generic,
    List,
    ParamSpec,
    Callable,
    Any,
    Concatenate,
    Tuple,
)
import enum
import functools
import json
from typing import (
    Any,
    Callable,
    Dict,
    ParamSpec,
)
from typing_extensions import Self

import httpx
from rich.console import Console
import typer


from client import flags
from client.flags import Output, Verbage
from client.config import Config
from rich.table import Table


# =========================================================================== #
# TYPES

V = ParamSpec("V")
# AsyncRequestFn = Callable[V, Coroutine[httpx.Response, Any, Any]]
RawFn = Callable[
    Concatenate[httpx.AsyncClient, V],
    Awaitable[httpx.Response],
]
RequestFn = Callable[V, Awaitable[httpx.Response]]
CommandFn = Callable[V, Awaitable[httpx.Response]]
TestFn = Callable[V, Awaitable[httpx.Response]]


class Mode(str, enum.Enum):
    test = "test"
    fn = "fn"
    cmd = "cmd"


# =========================================================================== #
# OUTPUTS

CONSOLE = Console()


class OuputHandler:
    output: Output
    columns: List[str]
    data: Any

    def __init__(
        self,
        output: Output = Output.json,
        columns: List[str] = list(),
    ):
        self.output = output
        self.columns = columns

    def print_table(self, res: httpx.Response, data=None) -> None:
        table = Table()
        data = data or res.json()
        if isinstance(data, dict):
            if not all(not isinstance(item, dict) for item in data):
                data = [data]
            else:
                data = list(
                    dict(uuid=uuid, **item) if "uuid" not in item else item
                    for uuid, item in data.items()
                )
        if not isinstance(data, list):
            raise ValueError(
                f"Results must be a coerced into a `list`, have `{type(data)}`."
            )

        keys = tuple(data[0].keys())
        if self.columns:
            keys = tuple(key for key in self.columns if keys)

        table.add_column("count")
        for count, key in enumerate(keys):
            table.add_column(
                key,
                style=typer.colors.BLUE if (count % 2) else typer.colors.BRIGHT_BLUE,
                justify="center",
            )

        if not data:
            CONSOLE.print("[green]No data to display.")
            return

        def norepeat(row: Dict[str, Any], row_last: Dict[str, Any], key: str):
            value_row_last, value_row = row_last.get(key), row.get(key)
            if value_row == value_row_last:
                return "`"
            return str(value_row)

        row_last: Dict[str, Any] = dict()
        for count, row in enumerate(data):
            flat = tuple(norepeat(row, row_last, key) for key in keys)
            table.add_row(str(count), *flat)
            row_last = row

        CONSOLE.print(table)

    def print_json(self, res: httpx.Response, data=None) -> None:
        data = res.json() or data
        CONSOLE.print_json(json.dumps(data))

    def __call__(
        self,
        res: httpx.Response,
        data=None,
    ) -> None:
        try:
            data = data if data is not None else res.json()
        except json.JSONDecodeError:
            data = None

        if not (200 <= res.status_code < 300):
            CONSOLE.print(f"[red]Recieved bad status code `{res.status_code}`.")
            if data:
                CONSOLE.print("[red]" + json.dumps(data, indent=2))
            raise typer.Exit(1)

        match self.output:
            case Output.json:
                self.print_json(res, data)
            case Output.table:
                self.print_table(res, data)


# =========================================================================== #


# NOTE: This should be what `RequestFn` is turned into by the metaclass.
class Fn(Generic[V]):
    mode: Mode
    fn: RequestFn
    test: RequestFn
    cmd: RequestFn

    def __init__(
        self,
        mode: Mode,
        fn: RequestFn,
        *,
        cmd: CommandFn | None = None,
        test: TestFn | None = None,
        test_callback: Callable | None = None,
    ):
        self.mode = mode
        self.fn = fn

        self.cmd = self.create_cmd() if cmd is None else cmd
        self.test = self.create_test(test_callback) if test is None else test

    def __call__(self) -> RequestFn:
        return self.fn

    def create_cmd(self) -> CommandFn:
        @functools.wraps(self.fn)
        async def cmd(*args: V.args, **kwargs: V.kwargs) -> httpx.Response:
            return await self.fn(*args, **kwargs)

        return cmd

    def create_test(self, callback: Callable | None = None) -> TestFn:
        @functools.wraps(self.fn)
        async def test(*args: V.args, **kwargs: V.kwargs) -> httpx.Response:
            res = await self.fn(*args, **kwargs)
            if callback:
                ...
            return res

        return test


class RequestMeta(type):
    def __new__(cls, name, base, namespace):
        # Check commands
        command, commands = namespace.get("command"), namespace.get("commands")
        if command is None:
            raise ValueError(f"`{name}` missing `command`.")

        if commands is None:
            raise AttributeError(f"`{name}` missing `commands`.")
        elif len(bad := [cc for cc in commands if cc not in namespace]):
            raise AttributeError(f"`{name}` missing commands `{bad}`.")
        elif len(
            bad := [cc for cc in commands if cc not in Verbage._value2member_map_]
        ):
            msg = f"`{name}.commands` contains illegal verbage `{bad}`."
            raise AttributeError(msg)

        # Decorate commands
        mode = namespace.get("mode", Mode.fn)
        fns = {cc: Fn(mode, namespace[cc]) for cc in commands}
        namespace["fns"] = fns
        namespace.update({cc: fn() for cc, fn in fns.items()})

        # Create type
        T = super().__new__(cls, name, base, namespace)

        return T


HandleOutput = Callable[[httpx.Response, "BaseRequest"], None]


class BaseRequest(metaclass=RequestMeta):
    command: ClassVar[str] = "base"
    children: ClassVar[Tuple[Type[Self], ...]] = tuple()
    commands: ClassVar[Tuple[str, ...]] = tuple()
    columns: ClassVar[List[str] | None] = None
    fns: ClassVar[Dict[str, Fn]]

    mode: Mode
    children_instances: Dict[str, "BaseRequest"]
    token: str | None
    config: Config
    _handle_output: HandleOutput | None  # Should be set by callback
    _client: httpx.AsyncClient | None
    _app: fastapi.FastAPI | None

    @classmethod
    def from_(cls, v: "BaseRequest") -> Self:
        return cls(
            handle_output=v._handle_output,
            client=v._client,
            app=v._app,
            config=v.config,
            token=v.token,
            mode=v.mode,
        )

    def __init__(
        self,
        config: Config,
        client: httpx.AsyncClient | None = None,
        token: str | None = None,
        *,
        children_instances: Dict[str, "BaseRequest"] = dict(),
        mode: Mode = Mode.fn,
        app: fastapi.FastAPI | None = None,
        handle_output: HandleOutput | None = None,
    ):
        self.config = config
        self._client = client

        self.children_instances = children_instances
        self.mode = mode
        self.token = token
        self._app = app
        self._handle_output = handle_output

    @functools.cached_property
    def handle_output(self) -> HandleOutput:
        if self._handle_output is None:
            msg = "Client has was not provided to constructor or set."
            raise ValueError(msg)
        return self._handle_output

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

        @functools.wraps(fn)
        async def wrapper(*args: V.args, **kwargs: V.kwargs):
            # print(2, args, kwargs)
            async with httpx.AsyncClient(
                base_url=self.config.host, app=self._app
            ) as client:
                self.client = client
                res = await fn(*args, **kwargs)
                self.handle_output(res)
            return res

        @functools.wraps(wrapper)
        def wrappersync(
            *args: V.args,
            **kwargs: V.kwargs,
        ) -> httpx.Response:
            # print(1, args, kwargs)
            res = asyncio.run(wrapper(*args, **kwargs))
            return res

        return wrappersync

    @functools.cached_property
    def typer(self) -> typer.Typer:
        # Necessary are the function from `fns` must be bound.
        if self.mode != Mode.cmd:
            raise ValueError("Typer not available when out of `cmd` mode.")

        t: typer.Typer = typer.Typer(callback=self.callback)
        for cmd, fn in self.fns.items():
            cmd_clean = cmd.replace("_", "-")
            decorator = t.command(cmd_clean)
            cmd_again = self.typerize(getattr(self, cmd))
            decorator(cmd_again)

        if not self.children_instances:
            self.children_instances = {
                child.command: child.from_(self) for child in self.children
            }

        for name, requester in self.children_instances.items():
            t.add_typer(requester.typer, name=name)

        return t

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
        self._handle_output = OuputHandler(output=output, columns=columns)
