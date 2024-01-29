import typer
from client import flags
import httpx
from client.flags import Output
from client.handlers import ConsoleHandler, CONSOLE
from client.requests.base import BaseRequest
from app.models import KindRecurse

__all__ = ("EventsRequests",)


class EventsRequests(BaseRequest):
    command = "events"
    commands = ("delete", "read", "search", "restore")

    def callback(
        self,
        output: flags.FlagOutput = Output.table,
        columns: flags.FlagColumns = list(),
    ):
        """Specify request output format."""
        self.output = output
        if not columns:
            columns = ["api_origin", "timestamp", "uuid_root"]
            columns += ["uuid_parent", "uuid", "kind", "kind_obj"]
            columns += ["uuid_obj", "detail"]
            self.columns = columns

        self.handler = ConsoleHandler(output=output, columns=columns, data=None)

    async def delete(self, uuid_event: flags.ArgUUIDEvent) -> httpx.Response:
        return await self.client.delete(
            f"/events/{uuid_event}",
            headers=self.headers,
        )

    async def read(
        self,
        uuid_event: flags.ArgUUIDEvent,
    ) -> httpx.Response:
        return await self.client.get(
            f"/events/{uuid_event}",
            headers=self.headers,
            params=dict(uuid_user=uuid_event),
        )

    async def search(
        self,
        flatten: flags.FlagFlatten = True,
        kind: flags.FlagKind = None,
        kind_obj: flags.FlagKindObject = None,
        uuid_obj: flags.FlagUUIDEventObject = None,
        recurse: flags.FlagKindRecurse = KindRecurse.depth_first,
    ) -> httpx.Response:
        params = dict(
            flatten=flatten,
            uuid_obj=uuid_obj,
            kind=kind.value if kind is not None else None,
            kind_obj=kind_obj.value if kind_obj is not None else None,
            recurse=recurse.value if recurse is not None else None,
        )
        params = {k: v for k, v in params.items() if v is not None}
        return await self.client.get(
            "/events",
            headers=self.headers,
            params=params,
        )

    async def restore(
        self,
        uuid_object: flags.FlagUUIDEventObject = None,
        uuid_event: flags.FlagUUIDEventOptional = None,
    ) -> httpx.Response:
        res = None
        match [uuid_object is None, uuid_event is None]:
            case [True, False]:
                res = await self.client.patch(
                    f"/events/{uuid_event}/objects", headers=self.headers
                )
            case [False, True]:
                res = await self.client.patch(
                    f"/events/objects/{uuid_object}", headers=self.headers
                )
            case [True, True] | [False | False] | _:
                CONSOLE.print(
                    "Exactly one of `--uuid-object` and `--uuid-event` must "
                    "be specified."
                )
                raise typer.Exit(1)

        return res

    # async def ws_watch(
    #     self,
    #     watcher: Callable[
    #         [websockets.WebSocketClientProtocol, Any],
    #         Awaitable[None],
    #     ],
    #     flatten: flags.FlagFlatten = True,
    #     kind: flags.FlagKind = None,
    #     kind_obj: flags.FlagKindObject = None,
    #     uuid_obj: flags.FlagUUIDEventObject = None,
    #     recurse: flags.FlagKindRecurse = KindRecurse.depth_first,
    # ) -> None:
    #     url = f"{self.config.host}/events"
    #     params = dict(
    #         flatten=flatten,
    #         kind=kind,
    #         kind_obj=kind_obj,
    #         uuid_obj=uuid_obj,
    #         recurse=recurse,
    #     )
    #     async with websockets.connect(url) as websocket:
    #         await websocket.send(params)
    #
    #         while res := await websocket.recv():
    #             await watcher(websocket, res)
    #
    # async def cmd_watch(
    #     self,
    #     flatten: flags.FlagFlatten = True,
    #     kind: flags.FlagKind = None,
    #     kind_obj: flags.FlagKindObject = None,
    #     uuid_obj: flags.FlagUUIDEventObject = None,
    #     recurse: flags.FlagKindRecurse = KindRecurse.depth_first,
    # ):
    #     async def console_watcher(
    #         websocket: websockets.WebSocketClientProtocol,
    #         res: Any,
    #     ) -> None:
    #         CONSOLE.print("[green]===================================================")
    #         CONSOLE.print(f"[green]Message Recv: {res}")
    #         req = CONSOLE.input("[green]Message Sent: ")
    #         await websocket.send(req)
    #
    #     params = dict(
    #         flatten=flatten,
    #         kind=kind,
    #         kind_obj=kind_obj,
    #         uuid_obj=uuid_obj,
    #         recurse=recurse,
    #     )
    #     return self.ws_watch(console_watcher, *params)
