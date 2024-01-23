import httpx
from typing import (
    Annotated,
    Generic,
    List,
    Any,
    Protocol,
    Self,
    TypeVar,
)
import json
from typing import (
    Any,
    Dict,
)

import httpx
from pydantic import BaseModel, Field
from rich.console import Console
import typer

from typing import Callable, Optional
from client import flags
from client.flags import Output
from rich.table import Table


# =========================================================================== #
# OUTPUTS

CONSOLE = Console()
# Handler = Callable[[httpx.Response, Optional[Any]], None]

T = TypeVar("T", covariant=True)


# NOTE: Usually a pydantic class with some chainable methods, expect `T` to be
#       self. The pydantic class will have data derived by flags (usually
#       created by a callback in typer or explicitly in tests).
class Handler(Protocol, Generic[T]):
    def __call__(self, res: httpx.Response, data: Any | None = None) -> T:
        ...


class ConsoleHandler(BaseModel):
    """Both data type and handler.

    This should be built by a handler somewhere.
    """

    # output: Annotated[Output, Field(default=Output.json)]
    # columns: Annotated[List[str], Field()]
    output: Annotated[flags.FlagOutput, Field(default=Output.json)]
    columns: Annotated[flags.FlagColumns, Field(default_factory=list)]
    data: Annotated[Any | None, Field(default=None)]

    def __call__(
        self,
        res: httpx.Response,
        data=None,
    ) -> Self:
        try:
            data = data if data is not None else res.json()
        except json.JSONDecodeError:
            data = None

        if not (200 <= res.status_code < 300):
            self.print_err(res, data)
            raise typer.Exit(1)

        match self.output:
            case Output.json:
                status = self.print_json(res, data)
            case Output.table:
                status = self.print_table(res, data)

        if status:
            raise typer.Exit(status)

        return self

    def print_err(self, res: httpx.Response, data=None) -> int:
        CONSOLE.print(f"[red]Request failed with status `{res.status_code}`.")
        if data:
            CONSOLE.print("[red]" + json.dumps(data, indent=2))
            return 1
        return 0

    def print_json(self, res: httpx.Response, data=None) -> int:
        data = res.json() or data
        try:
            stringified = json.dumps(data)
        except TypeError as err:
            CONSOLE.print("[red]Failed to decode response JSON.")
            CONSOLE.print(f"[red]{str(err)}")
            return 1

        CONSOLE.print_json(stringified)
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

        if not self.columns or "count" in self.columns:
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
            table.add_row(str(count), *flat)
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
            raise ValueError(
                f"Results must be a coerced into a `list`, have `{type(data)}`."
            )

        return data
