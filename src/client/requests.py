import enum
from typing import (
    Any,
    Dict,
    ParamSpec,
    TypeVar,
)

import httpx
import typer
import yaml
from app.models import (
    ChildrenCollection,
    ChildrenUser,
    LevelStr,
)
from app.models import KindRecurse


from client import flags
from client.flags import Output
from client.base import BaseRequest
from client.handlers import CONSOLE, ConsoleHandler


T, S = TypeVar("T"), TypeVar("S")


def params(**kwargs) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


class DocumentRequests(BaseRequest):
    command = "documents"
    commands = ("read", "search")

    async def read(self, uuid_document: flags.ArgUUIDDocument) -> httpx.Response:
        url = f"/documents/{uuid_document}"
        return await self.client.get(url, headers=self.headers)

    async def search(
        self,
        limit: flags.FlagLimit = 10,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
    ):
        return await self.client.get(
            "/documents",
            params=params(
                limit=limit,
                name_like=name_like,
                description_like=description_like,
            ),
            headers=self.headers,
        )


class CollectionRequests(BaseRequest):
    command = "collections"
    commands = ("read", "create", "delete", "update")

    async def read(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        child: flags.FlagChildrenCollection | None = None,
        uuid_child: flags.FlagUUIDChildrenOptional = list(),
    ) -> httpx.Response:
        params: Dict[str, Any] = dict()
        match [child, not len(uuid_child)]:
            case [None, True]:
                pass
            case [ChildrenCollection.documents, _]:
                params.update(uuid_document=uuid_child)
            case [ChildrenCollection.edits, _]:
                params.update(uuid_edit=uuid_child)
            case _:
                CONSOLE.print(
                    "[red]`--uuid-child` can only be used when `--child` is "
                    "provided."
                )
                raise typer.Exit(1)

        # Determine URL
        url_parts = ["collections", uuid_collection]
        if child is not None:
            url_parts.append(child)
        url = "/" + "/".join(url_parts)
        return await self.client.get(url, params=params, headers=self.headers)

    async def create(
        self,
        name: flags.FlagName = None,
        description: flags.FlagDescription = None,
        public: flags.FlagPublicOptional = None,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
    ) -> httpx.Response:
        return await self.client.post(
            "/collections",
            params=dict(uuid_document=uuid_document),
            json=dict(name=name, description=description, public=public),
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        restore: flags.FlagRestore = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/collections/{uuid_collection}",
            params=dict(restore=restore),
            headers=self.headers,
        )

    async def update(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        name: flags.FlagName = None,
        description: flags.FlagDescription = None,
        public: flags.FlagPublicOptional = None,
        uuid_user: flags.FlagUUIDUserOptional = None,
    ) -> httpx.Response:
        params = dict(
            name=name,
            description=description,
            public=public,
            uuid_user=uuid_user,
        )
        params = {k: v for k, v in params.items() if v is not None}
        return await self.client.patch(
            f"/collections/{uuid_collection}",
            params=params,
            headers=self.headers,
        )


class UserRequests(BaseRequest):
    command = "users"
    commands = ("read", "search", "update", "create", "delete")

    async def search(
        self,
        limit: flags.FlagLimit = 10,
        name_like: flags.FlagNameLike = None,
    ):
        return await self.client.get(
            "/users",
            headers=self.headers,
            params=params(limit=limit, name_like=name_like),
        )

    async def read(
        self,
        uuid_user: flags.ArgUUIDUser,
        child: flags.FlagChildrenUser = None,
        child_uuids: flags.FlagUUIDChildrenOptional = list(),
    ):
        params = dict()
        match [child, bool(len(child_uuids))]:
            case [None, False]:
                pass
            case [None, True]:
                CONSOLE.print(
                    "[red]`child_uuids` can only be specified when `child` is too."
                )
                raise typer.Exit(1)
            case [ChildrenUser.collections, _]:
                params["uuid_collection"] = child_uuids
            case [ChildrenUser.documents, _]:
                params["uuid_document"] = child_uuids
            case _:
                CONSOLE.print(
                    "[red]Invalid combination of `--child` and `--uuid-child`.",
                )
                raise typer.Exit(2)

        url_parts = ["users", uuid_user]
        if child is not None:
            url_parts.append(child)

        url = "/" + "/".join(url_parts)
        return await self.client.get(
            url,
            params=params,
            headers=self.headers,
        )

    async def update(
        self,
        uuid_user: flags.ArgUUIDUser,
        name: flags.FlagName = None,
        description: flags.FlagDescription = None,
        url: flags.FlagUrl = None,
        url_image: flags.FlagUrlImage = None,
        public: flags.FlagPublic = None,
    ) -> httpx.Response:
        params = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
        )
        params = {k: v for k, v in params.items() if v is not None}
        return await self.client.patch(
            f"/users/{uuid_user}",
            params=params,
            headers=self.headers,
        )

    async def create(
        self,
        filepath: str,
    ) -> httpx.Response:
        with open(filepath, "r") as file:
            content = yaml.safe_load(file)

        return await self.client.post(
            "/users",
            json=content,
            headers=self.headers,
        )

    async def delete(
        self, uuid_user: flags.ArgUUIDUser, restore: flags.FlagRestore = False
    ) -> httpx.Response:
        return await self.client.delete(
            f"/users/{uuid_user}",
            params=dict(uuid_user=uuid_user, restore=restore),
            headers=self.headers,
        )


class AssignmentRequests(BaseRequest):
    command = "assignments"
    commands = ("read", "create", "delete")

    async def read(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
    ):
        params: Dict[str, Any] = dict()
        if uuid_document:
            params.update(uuid_document=uuid_document)
        return await self.client.get(
            f"/assignments/collections/{uuid_collection}",
            params=params,
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        uuid_document: flags.FlagUUIDDocuments,
        restore: flags.FlagRestore = False,
    ):
        return await self.client.delete(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document, restore=restore),
            headers=self.headers,
        )

    async def create(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        uuid_document: flags.FlagUUIDDocuments,
    ):
        return await self.client.post(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document),
            headers=self.headers,
        )


class GrantRequests(BaseRequest):
    command = "grants"
    commands = ("read_document", "read_user", "create", "delete")

    async def read_user(
        self,
        uuid_user: flags.ArgUUIDUser,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
    ) -> httpx.Response:
        params: Dict[str, Any] = dict()
        if uuid_document is not None:
            params.update(uuid_document=uuid_document)
        return await self.client.get(
            f"/grants/users/{uuid_user}",
            params=params,
            headers=self.headers,
        )

    async def read_document(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_user: flags.FlagUUIDUsersOptional = None,
    ) -> httpx.Response:
        params: Dict[str, Any] = dict()
        if uuid_user:
            params.update(uuid_user=uuid_user)
        return await self.client.get(
            f"/grants/documents/{uuid_document}",
            params=params,
            headers=self.headers,
        )

    async def create(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_user: flags.FlagUUIDUsers,
        level: flags.FlagLevel = LevelStr.view,
    ) -> httpx.Response:
        return await self.client.post(
            f"/grants/documents/{uuid_document}",
            json=[
                dict(
                    uuid_user=uu,
                    level=level.name,
                )
                for uu in uuid_user
            ],
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_user: flags.FlagUUIDUsers,
        restore: flags.FlagRestore = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/grants/documents/{uuid_document}",
            headers=self.headers,
            params=dict(uuid_user=uuid_user, restore=restore),
        )


class EventsRequests(BaseRequest):
    command = "events"
    commands = ("read", "search", "restore")

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

        self.handler = ConsoleHandler(
            output=output,
            columns=columns,
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
        print(self.handler)
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


class RequestsEnum(enum.Enum):
    users = UserRequests
    collections = CollectionRequests
    documents = DocumentRequests
    grants = GrantRequests
    assignments = AssignmentRequests
    events = EventsRequests


class Requests(BaseRequest):
    command = "main"
    commands = tuple()
    children = tuple(rr.value for rr in RequestsEnum)

    users: UserRequests
    collections: CollectionRequests
    documents: DocumentRequests
    grants: GrantRequests
    assignments: AssignmentRequests
    events: EventsRequests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for child in self.children:
            child = RequestsEnum._value2member_map_[child]
            setattr(self, child.name, child.value.from_(self))

    def update_token(self, token: str):
        self._token = token
        for ee in RequestsEnum:
            requester = getattr(self, ee.name)
            requester._token = token

    def callback(
        self,
        profile: flags.FlagProfile = None,
        host: flags.FlagHost = None,
    ) -> None:
        """Update configuration from typer flags.

        Put this in `typer.callback`."""
        if profile is not None:
            self.config.use.profile = profile
        if self.config.profile is None:
            CONSOLE.print(f"Missing configuration for host `{profile}`.")
            raise typer.Exit(1)

        if host is not None:
            self.config.use.host = host
        if self.config.host is None:
            CONSOLE.print(f"Missing configuration for host `{profile}`.")
            raise typer.Exit(1)
