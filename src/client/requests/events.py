from datetime import datetime

import httpx
import typer
from app.models import KindObject, KindRecurse, Singular
from client import flags
from client.flags import Output
from client.handlers import CONSOLE, ConsoleHandler
from client.requests.base import BaseRequest, params

__all__ = ("EventsRequests",)


class EventsRequests(BaseRequest):
    command = "events"
    commands_check_verbage = False
    commands = ("prune", "read", "search", "restore", "objects")

    def callback(
        self,
        output: flags.FlagOutput = Output.yaml,
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


    async def prune(
        self, 
        kind_obj: flags.ArgKindObject,
        uuid_obj: flags.ArgUUIDEvent,
        root: bool = False,
    ) -> httpx.Response:
        p = params(root=root)
        if kind_obj == KindObject.event:
            return await self.client.delete(
                f"/events/{uuid_obj}",
                headers=self.headers,
                params=p
            )
        return await self.client.delete(
            f"/events/{Singular(kind_obj.name).name}/{uuid_obj}",
            headers=self.headers,
            params=p,
        )

    async def read(
        self,
        kind_obj: flags.ArgKindObject,
        uuid_obj: flags.ArgUUIDEvent,
        root: bool = False,
    ) -> httpx.Response:
        if kind_obj == KindObject.event:
            return await self.client.get(
                f"/events/{uuid_obj}",
                headers=self.headers,
                params=dict(root=root),
            )

        # NOTE: Across many controllers.
        kind_object_plural = Singular(kind_obj.name).name
        return await self.client.get(
            f"/{kind_object_plural}/{uuid_obj}/events",
            params=params(root=root),
            headers=self.headers,
        )


    async def search(
        self,
        # recurse: flags.FlagKindRecurse = KindRecurse.depth_firsut, 
        # flatten: flags.FlagFlatten = True,
        kind: flags.FlagKind = None,
        kind_obj: flags.FlagKindObjectOptional = None,
        uuid_obj: flags.FlagUUIDEventObjectOptional = None,
        uuid_event: flags.FlagUUIDEventsOptional = None,
        before: flags.FlagBefore = None,
        after: flags.FlagAfter = None,
    ) -> httpx.Response:
        res = await self.client.get(
            "/events",
            headers=self.headers,
            params=(p:=params(
                # flatten=flatten,
                # recurse=recurse.value if recurse is not None else None,
                before=datetime.timestamp(before) if before is not None else before,
                after=datetime.timestamp(after) if after is not None else after,
                uuid_event=uuid_event,
                uuid_obj=uuid_obj,
                kind=kind.value if kind is not None else None,
                kind_obj=kind_obj.value if kind_obj is not None else None,
            ))
        )
        return res

    async def restore(
        self,
        uuid_object: flags.FlagUUIDEventObjectOptional = None,
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

    async def objects(
        self,
        uuid_event: flags.ArgUUIDEvent,
        root: bool = False,
    ) -> httpx.Response:

        return await self.client.get(
            f"/events/{uuid_event}/objects",
            params=params(root=root),
        )

    # async def ws_watch(
    #     self,
    #     watcher: Callable[
    #         [websockets.WebSocketClientProtocol, Any],
    #         Awaitable[None],
    #     ],
    #     flatten: flags.FlagFlatten = True,
    #     kind: flags.FlagKind = None,
    #     kind_obj: flags.FlagKindObject = None,
    #     uuid_obj: flags.FlagUUIDEventObjectOptional = None,
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
    #     uuid_obj: flags.FlagUUIDEventObjectOptional = None,
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
