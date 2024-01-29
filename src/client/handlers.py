import re
import asyncio
import httpx
from typing import (
    Annotated,
    Generic,
    List,
    Any,
    Protocol,
    Self,
    Tuple,
    TypeVar,
    overload,
)
import json
from typing import (
    Any,
    Dict,
)

from pydantic import BaseModel, Field
from rich.console import Console
import typer
from rich.syntax import Syntax, SyntaxTheme

from typing import Callable, Optional

import yaml
from client import flags
from client.flags import Output
from rich.table import Table


# =========================================================================== #
# Types and Constants
# About `CONSOLE_THEME`: https://pygments.org/docs/styles/#getting-a-list-of-available-styles

CONSOLE_THEME = "fruity"
CONSOLE = Console()


class Handler(Protocol):
    @overload
    async def __call__(
        self,
        res: httpx.Response,
        data: Any | None = None,
    ) -> httpx.Response:
        ...

    @overload
    async def __call__(
        self,
        res: httpx.Response | Tuple[httpx.Response, ...],
        data: Any | Tuple[Any, ...] | None = None,
    ) -> httpx.Response:
        ...

    async def __call__(
        self,
        res: httpx.Response | Tuple[httpx.Response, ...],
        data: Any | Tuple[Any, ...] | None = None,
    ) -> httpx.Response:
        ...

    @overload
    async def handle(
        self,
        res: httpx.Response,
        data: Any | None = None,
    ) -> int:
        ...

    @overload
    async def handle(
        self,
        res: Tuple[httpx.Response, ...],
        data: Tuple[Any, ...] | None = None,
    ) -> int:
        ...

    async def handle(
        self,
        res: httpx.Response | Tuple[httpx.Response, ...],
        data: Any | Tuple[Any, ...] | None = None,
    ) -> int:
        ...


# =========================================================================== #
# Handler instances.


class ConsoleHandler(BaseModel):
    """Both data type and handler.

    This should be built by a handler somewhere.
    """

    output: Annotated[flags.FlagOutput, Field(default=Output.json)]
    columns: Annotated[flags.FlagColumns, Field(default_factory=list)]
    data: Annotated[Any | None, Field(default=None)]

    async def __call__(
        self,
        res: httpx.Response,
        data=None,
    ) -> httpx.Response:
        status = await self.handle(res, data)
        raise typer.Exit(status)

    async def handle(
        self,
        res: httpx.Response | Tuple[httpx.Response, ...],
        data: Any | Tuple[Any, ...] = None,
    ) -> int:
        match [res, data]:
            case [[*items], [*data]]:
                items = zip(items, data)
                return sum((self.handle_one(*item) for item in items))
            case [httpx.Response, data]:
                return self.handle_one(res, data)
            case _:
                raise ValueError()

    def handle_one(
        self,
        res: httpx.Response,
        data: Any | None = None,
    ) -> int:
        try:
            data = data if data is not None else res.json()
        except json.JSONDecodeError:
            data = None

        if not (200 <= res.status_code < 300):
            self.print_err(res, data)
            return 1

        match self.output:
            case Output.json:
                return self.print_json(res, data)
            case Output.table:
                return self.print_table(res, data)
            case Output.yaml:
                return self.print_yaml(res, data)
            case _ as bad:
                CONSOLE.print(f"[red]Unknown output format `{bad}`.")
                return 1

    def print_err(self, res: httpx.Response, data=None) -> int:
        CONSOLE.print(f"[red]Request failed with status `{res.status_code}`.")
        if data:
            CONSOLE.print("[red]" + json.dumps(data, indent=2))
            return 1
        return 0

    def print_json(self, res: httpx.Response, data=None) -> int:
        data = res.json() or data
        try:
            stringified = json.dumps(data, indent=2)
        except TypeError as err:
            CONSOLE.print("[red]Failed to decode response JSON.")
            CONSOLE.print(f"[red]{str(err)}")
            return 1

        CONSOLE.print(Syntax(stringified, "json", theme=CONSOLE_THEME))
        return 0

    def print_yaml(self, res: httpx.Response, data=None) -> int:
        data = res.json() or data
        try:
            stringified = yaml.dump(data)
        except yaml.YAMLError as err:
            CONSOLE.print("[red]Failed to decode response JSON.")
            CONSOLE.print(f"[red]{str(err)}")
            return 1

        stringified = "# YAML Ouput\n---\n" + stringified
        CONSOLE.print(Syntax(stringified, "yaml", theme=CONSOLE_THEME))
        return 0

    def print_table(self, res: httpx.Response, data=None) -> int:
        data = res.json() or data
        table = self.create_table(res, data)
        if table is None:
            return 1
        CONSOLE.print(table)
        return 0

    def create_table(self, res: httpx.Response, data=None) -> Table | None:
        table = Table()
        if not (data := self.unfuck(data or res.json())):
            CONSOLE.print("[green]No data to display.")
            return None

        # Create columns
        keys = tuple(data[0].keys())
        if self.columns:
            keys = tuple(key for key in self.columns if keys)

        if include_count := not self.columns or "count" in self.columns:
            table.add_column("count")

        for ii, key in enumerate(keys):
            style = typer.colors.BLUE if (ii % 2) else typer.colors.BRIGHT_BLUE
            table.add_column(
                key,
                style=style,
                justify="center",
            )

        # Add rows
        def omit(row: Dict[str, Any], row_last: Dict[str, Any], key: str):
            value_row_last, value_row = row_last.get(key), row.get(key)
            if value_row == value_row_last:
                return "`"
            return str(value_row)

        row_last: Dict[str, Any] = dict()
        for count, row in enumerate(data):
            flat = tuple(omit(row, row_last, key) for key in keys)
            if include_count:
                table.add_row(str(count), *flat)
            else:
                table.add_row(*flat)
            row_last = row

        return table

    def unfuck(self, data):
        if isinstance(data, dict):
            if not all(not isinstance(item, dict) for item in data):
                data = [data]
            else:
                data = list(
                    dict(uuid=uuid, **item) if "uuid" not in item else item
                    for uuid, item in data.items()
                )
        if not isinstance(data, list):
            msg = "Results must be a coerced into a `list` "
            msg += f"(is `{type(data)}`)."
            raise ValueError(msg)

        return data


# foo: Handler = ConsoleHandler(output=Output.json, columns=list(), data=None)
