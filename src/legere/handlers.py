# =========================================================================== #
import json
from http import HTTPMethod
from typing import Any, ClassVar, Generic, Iterable, Protocol, Tuple, Type, TypeVar

import httpx
import yaml
from pydantic import BaseModel, TypeAdapter, ValidationError
from rich.align import Align, AlignMethod, VerticalAlignMethod
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

# --------------------------------------------------------------------------- #
from captura.err import ErrDetail
from captura.schemas import mwargs
from legere.config import Config, OutputConfig
from legere.flags import Output

# Types and Constants
# About `CONSOLE_THEME`: https://pygments.org/docs/styles/#getting-a-list-of-available-styles

CONSOLE_THEME = "fruity"
CONSOLE = Console()


# NOTE: Old table stuff.
# def print_table(self, res: httpx.Response, data=None) -> int:
#     data = res.json() or data
#     table = self.create_table(res, data)
#     if table is None:
#         return 1
#     CONSOLE.print(table)
#     return 0
#
# def create_table(self, res: httpx.Response, data=None) -> Table | None:
#     table = Table()
#     if not (data := self.unfuck(data or res.json())):
#         CONSOLE.print("[green]No data to display.")
#         return None
#
#     # Create columns
#     keys = tuple(data[0].keys())
#     if self.columns:
#         keys = tuple(key for key in self.columns if keys)
#
#     if include_count := not self.columns or "count" in self.columns:
#         table.add_column("count")
#
#     column_config_base = dict(
#         justify="center",
#     )
#
#     for ii, key in enumerate(keys):
#         column_config_extra = self.column_configs.get(key, dict())
#         column_config: Dict[str, Any]
#         column_config = column_config_base | column_config_extra
#
#         if column_config.get("style") is None:
#             style = typer.colors.CYAN if not (ii % 2) else typer.colors.BLUE
#             column_config.update(style=style)
#
#         table.add_column(key, **column_config)
#
#     # Add rows
#     def omit(row: Dict[str, Any], row_last: Dict[str, Any], key: str):
#         value_row_last, value_row = row_last.get(key), row.get(key)
#         if value_row == value_row_last:
#             return "`"
#         if isinstance(value_row, list):
#             value_row = ", ".join(value_row)
#         return str(value_row)
#
#     row_last: Dict[str, Any] = dict()
#     for count, row in enumerate(data):
#         flat = tuple(omit(row, row_last, key) for key in keys)
#         if include_count:
#             table.add_row(str(count), *flat)
#         else:
#             table.add_row(*flat)
#         row_last = row
#
#     return table
#
# def unfuck(self, data):
#     if isinstance(data, dict):
#         if not all(not isinstance(item, dict) for item in data):
#             data = [data]
#         else:
#             data = list(
#                 dict(uuid=uuid, **item) if "uuid" not in item else item
#                 for uuid, item in data.items()
#             )
#     if not isinstance(data, list):
#         msg = "Results must be a coerced into a `list` "
#         msg += f"(is `{type(data)}`)."
#         raise HandlerError(msg)
#
#     return data

T_HandlerData = TypeVar("T_HandlerData")


class BaseHandlerData(Generic[T_HandlerData]):

    data: Any
    output_config: OutputConfig
    adapter: TypeAdapter[T_HandlerData] | None

    def __init__(
        self,
        data: T_HandlerData | None = None,
        output_config: OutputConfig | None = None,
        adapter: TypeAdapter[T_HandlerData] | None = None,
    ) -> None:
        self.data = data
        self.adapter = adapter
        self.output_config = output_config or mwargs(OutputConfig)

    def __rich__(self) -> Layout | Panel | str:
        render, _ = self.render()
        return render

    def __str__(self):
        return self.render_raw(output=Output.json)

    def print(self) -> int:
        rendered, exit_code = self.render()
        if self.output_config.output == Output.raw and isinstance(rendered, str):
            print(rendered)
        else:
            CONSOLE.print(rendered)
        return exit_code

    def data_jsonable(self, data: Any | None = None) -> Any:
        data = data or self.data
        if self.adapter is not None:
            return self.adapter.dump_python(data)

        return data

    def render(
        self,
        *,
        data: Any | None = None,
        output: Output | None = None,
        decorate: bool | None = None,
    ) -> Tuple[Any, int]:

        # NOTE: Print both the request and response. This will be used in
        #       pytest too.
        rendered: Any
        match (output or self.output_config.output):
            case Output.json:
                rendered = self.render_json(data=data, decorate=decorate)
            case Output.yaml:
                rendered = self.render_yaml(data=data, decorate=decorate)
            case Output.table:
                rendered = self.render_table(data=data)
            case Output.raw:
                rendered = self.render_raw(
                    data=data,
                    output=Output.json,
                )
            case _ as bad:
                raise ValueError(f"Unknown output format `{bad}`.")

        return rendered, 0

    def render_raw(
        self,
        *,
        data: Any | None = None,
        output: Output | None = None,
        **kwargs,
    ) -> str:
        match (output if output is not None else self.output_config.output):
            case Output.yaml:
                return "---\n" + yaml.dump(self.data_jsonable(data=data), **kwargs)
            case Output.json:
                return json.dumps(self.data_jsonable(data=data), **kwargs)
            case bad:
                raise ValueError(f"Cannot dump for kind `{bad}` in raw mode.")

    def render_json(
        self,
        align: AlignMethod = "left",
        vertical: VerticalAlignMethod = "middle",
        *,
        data: Any | None = None,
        decorate: bool | None = None,
    ) -> Panel:
        jj: Any = Syntax(
            self.render_raw(data=data, output=Output.json, indent=2),
            "json",
            theme=self.output_config.rich_theme,
            word_wrap=True,
            background_color="default",
        )
        jj = Align(jj, align, vertical=vertical)
        if decorate or self.output_config.decorate:
            jj = Panel(jj)
        return jj

    def render_yaml(
        self,
        align: AlignMethod = "left",
        vertical: VerticalAlignMethod = "middle",
        *,
        data: Any | None = None,
        decorate: bool | None = None,
    ) -> Panel:
        jj: Any = Syntax(
            self.render_raw(data=data, output=Output.yaml),
            "yaml",
            theme=self.output_config.rich_theme,
            word_wrap=True,
            background_color="default",
        )
        jj = Align(jj, align, vertical=vertical)
        if decorate or self.output_config.decorate:
            jj = Panel(jj)
        return jj

    def render_table(self, *, data: Any | None = None) -> Layout:
        raise ValueError("Table rendering is not available at this time.")


class HandlerData(BaseHandlerData[T_HandlerData]):
    """Use this to render data that has no request.

    This keeps the logic for requests entirely separate.
    """

    ...


class RequestHandlerData(BaseHandlerData[T_HandlerData]):

    response: httpx.Response
    expect_status: int
    expect_err: ErrDetail | None

    def __init__(
        self,
        response: httpx.Response,
        adapter: Type[BaseModel] | TypeAdapter[T_HandlerData] | None = None,
        *,
        data: T_HandlerData | None = None,
        output_config: OutputConfig | None = None,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
    ) -> None:
        self.output_config = output_config or mwargs(OutputConfig)
        self.expect_err = expect_err

        adapter_final: TypeAdapter | None
        if adapter is not None and not isinstance(adapter, TypeAdapter):
            adapter_final = TypeAdapter(adapter)
        else:
            adapter_final = adapter

        self.set_data(response, adapter_final, data=data, expect_status=expect_status)

    def set_data(
        self,
        response: httpx.Response,
        adapter: TypeAdapter[T_HandlerData] | None = None,
        *,
        data: T_HandlerData | None = None,
        expect_status: int | None = None,
    ) -> None:

        self.response = response
        if expect_status is None:
            match response.request.method:
                case HTTPMethod.POST:
                    expect_status = 201
                case _:
                    expect_status = 200

        self.expect_status = expect_status

        match [adapter, data]:
            case [None, None]:
                try:
                    self.data = response.json() if response.content else None
                except json.JSONDecodeError:
                    self.data = None

                self.adapter = None
            case [TypeAdapter() as adptr, dd]:
                if data is None:
                    try:
                        self.data = adptr.validate_json(response.content)
                    except ValidationError:
                        msg = "Failed to handle response with adapter `%s`." % adptr
                        CONSOLE.print(msg)
                        self.data = response.json() if response.content else None
                else:
                    self._data = adptr.validate_python(dd)
                self.adapter = adptr
            case [None, dd] if dd is not None:
                self.data = dd
                self.adapter = None
            case _:
                raise ValueError("Cannot set from data.")

        return None

    def render(
        self,
        *,
        data: Any | None = None,
        output: Output | None = None,
        decorate: bool | None = None,
    ) -> Tuple[Any, int]:
        res = self.response
        if res.status_code != self.expect_status:
            return (self.render_err(), 1)
        return super().render(data=data, output=output, decorate=decorate)

    def render_err(self) -> Table | None:
        """Return the response as rendered by :meth:`render_request` only when
        the status code is bad."""

        if self.expect_status != self.response.status_code:
            table = self.render_response()
            table.title = Text("Request Failed", style="bold red")
            return table

        if self.expect_err is None:
            return None

        return self.expect_err.compare(self.response)

    def render_response(self) -> Table:
        """Does not necessarily have to render an error."""

        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column()
        table.add_column()

        table.add_row(
            Text("Response Status Expected:", style="bold red"),
            Text(str(self.expect_status), style="bold yellow"),
        )
        table.add_row(
            Text("Response Status Recieved:", style="bold red"),
            Text(str(self.response.status_code), style="bold yellow"),
        )

        if self.response.content:
            try:
                response_data = self.response.json()
            except json.JSONDecodeError:
                response_data = None
        else:
            response_data = None

        response_data_handler: HandlerData = HandlerData(
            output_config=self.output_config,
            data=response_data,
        )
        table.add_row(
            Text("Response Content:", style="bold red"),
            response_data_handler.render(output=Output.raw)[0],
        )
        table.add_row()
        table.add_row(
            Text("Response Headers:", style="bold red"),
            render_headers(self.response),
        )

        self.render_request(table=table)
        return table

    def render_request(self, table: Table | None = None):
        return render_request(
            self.output_config,
            self.response.request,
            table=table,
        )


def render_headers(has_headers: httpx.Response | httpx.Request) -> Table:

    table = Table(box=None, pad_edge=False, show_header=False)
    table.add_column(width=16)
    table.add_column(no_wrap=False, overflow="ellipsis")
    for key, value in has_headers.headers.items():
        table.add_row(key, value)

    return table


def render_request(
    output_config: OutputConfig,
    request: httpx.Request,
    table: Table | None = None,
    # max_content_length: int | None = 4096,
) -> Table:

    if table is None:
        table = Table(show_header=False, box=None, pad_edge=False)
    else:
        table.add_row()

    table.add_row(
        Text("Request Method:", style="bold green"),
        Text(str(request.method), "bold yellow"),
    )
    table.add_row(
        Text("Request URL:", style="bold green"),
        Text(str(request.url), style="bold yellow"),
    )

    response_data = json.loads(request.content) if request.content else None
    response_data_handler: HandlerData = HandlerData(
        output_config=output_config,
        data=response_data,
    )
    table.add_row(
        Text("Request Content:", style="bold green"),
        response_data_handler.render(output=Output.raw)[0],
    )
    table.add_row()
    table.add_row(
        Text("Request Headers:", style="bold green"),
        render_headers(request),
    )

    return table


T_RequestHandlerReturn = TypeVar("T_RequestHandlerReturn", covariant=True)
ResolvableRequestHandlerDatas = Tuple[RequestHandlerData, ...] | RequestHandlerData
ResolvableHandlerDatas = Tuple[HandlerData, ...] | HandlerData


class BaseRequestHandler(Protocol, Generic[T_RequestHandlerReturn]):
    console: ClassVar[Console] = CONSOLE
    config: Config

    def __init__(self, config: Config):
        self.config = config

    def __call__(
        self,
        res: httpx.Response | Iterable[httpx.Response] | None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
        handler_data: ResolvableHandlerDatas | None = None,
    ) -> T_RequestHandlerReturn: ...

    def handle(
        self,
        response: httpx.Response | Iterable[httpx.Response] | None = None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
        handler_data: ResolvableHandlerDatas | None = None,
    ) -> T_RequestHandlerReturn:
        return self(
            response,
            data,
            adapter,
            expect_err=expect_err,
            expect_status=expect_status,
            request_handler_data=request_handler_data,
            handler_data=handler_data,
        )

    def resolve(
        self,
        response: httpx.Response | Iterable[httpx.Response] | None = None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
    ) -> Tuple[RequestHandlerData, ...]:

        request_handler_datas: Tuple[RequestHandlerData, ...]
        match (response, request_handler_data):
            case (httpx.Response() as response, None):
                responses = (response,)
            case ([*responses], None):
                ...
            case (None, RequestHandlerData() as hd):
                return (hd,)
            case bad:
                raise ValueError(
                    f"Must specify exactly one of `requests` and "
                    f"`request_handler_data`. Input = `{bad}`."
                )

        request_handler_datas = tuple(
            RequestHandlerData(
                response=rr,
                data=data,
                adapter=adapter,
                output_config=self.config.output,
                expect_err=expect_err,
                expect_status=expect_status,
            )
            for rr in responses
        )

        return request_handler_datas

    def collect(
        self, request_handler_datas: Tuple[RequestHandlerData, ...]
    ) -> Tuple[Table, ...]:

        return tuple(
            table
            for handler_data in request_handler_datas
            if (table := handler_data.render_err()) is not None
        )


class ConsoleHandler(BaseRequestHandler[int]):
    def __call__(
        self,
        response: httpx.Response | Iterable[httpx.Response] | None = None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
        handler_data: ResolvableHandlerDatas | None = None,
    ) -> int:

        if request_handler_data is not None or response is not None:
            if handler_data:
                raise ValueError(
                    "Cannot specify `handler_data` when "
                    "`request_handler_data` can be resolved."
                )
            request_handler_datas = self.resolve(
                response,
                data,
                adapter,
                expect_err=expect_err,
                expect_status=expect_status,
                request_handler_data=request_handler_data,
            )

            exit_code = 0
            for rhd in request_handler_datas:
                exit_code += rhd.print()

            return exit_code

        assert handler_data is not None
        if isinstance(handler_data, tuple):
            handler_datas = handler_data
        else:
            handler_datas = (handler_data,)

        exit_code = 0
        for hd in handler_datas:
            exit_code += hd.print()

        return exit_code


# TODO: Come back here!
class AssertionHandler(BaseRequestHandler[Tuple[RequestHandlerData, ...]]):

    def __call__(
        self,
        response: httpx.Response | Iterable[httpx.Response] | None = None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
        handler_data: ResolvableHandlerDatas | None = None,
    ) -> Tuple[RequestHandlerData, ...]:

        if handler_data is not None:
            msg = "`AssertionHandler` does not accept `handler_data`."
            raise ValueError(msg)

        request_handler_datas, err = self.check_status(
            response,
            data,
            adapter,
            expect_err=expect_err,
            expect_status=expect_status,
            request_handler_data=request_handler_data,
        )
        if err is not None:
            raise err

        return request_handler_datas

    def check_status(
        self,
        response: httpx.Response | Iterable[httpx.Response] | None = None,
        data: Any | Tuple[Any, ...] | None = None,
        adapter: TypeAdapter | None = None,
        *,
        expect_err: ErrDetail | None = None,
        expect_status: int | None = None,
        request_handler_data: ResolvableRequestHandlerDatas | None = None,
    ) -> Tuple[
        Tuple[RequestHandlerData, ...],
        AssertionError | None,
    ]:
        request_handler_datas = self.resolve(
            response,
            data,
            adapter,
            expect_err=expect_err,
            expect_status=expect_status,
            request_handler_data=request_handler_data,
        )

        err = None
        if err_table := self.compile(self.collect(request_handler_datas)):
            with self.console.capture() as capture:
                self.console.print(err_table)

            err = AssertionError(capture.get())

        return request_handler_datas, err

    def compile(self, err_tables: Tuple[Table, ...]) -> Table | None:
        if len(err_tables) == 0:
            return None

        tt = Table(show_header=False, title="Errors")
        tt.add_column()
        for err_table in err_tables:
            tt.add_section()
            err_table.title = None
            tt.add_row(err_table)

        return tt
