import asyncio
import enum
import functools
import inspect
import json
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Coroutine,
    Dict,
    List,
    Optional,
    ParamSpec,
    Tuple,
    Type,
    TypeAlias,
)
from typing_extensions import Self

import httpx
import rich
from rich.console import Console
import typer
import yaml
from app.models import (
    ChildrenDocument,
    KindEvent,
    Level,
    ChildrenCollection,
    ChildrenUser,
    LevelStr,
    KindObject,
)
from app.schemas import UserUpdateSchema
from app.views import KindRecurse

from client.config import Config

# =========================================================================== #
# Typer Flags and Args.

CONSOLE = Console()


class Verbage(str, enum.Enum):
    read = "read"
    search = "search"
    restore = "restore"
    update = "update"
    delete = "delete"
    create = "create"

    apply = "apply"
    destroy = "destroy"


class Output(str, enum.Enum):
    json = "json"
    table = "table"


# --------------------------------------------------------------------------- #
# UUID Flags and Arguments
# NOTE: Annotations should eventually include help.

FlagOutput: TypeAlias = Annotated[Output, typer.Option("--output", "-o")]
FlagUUIDChildrenOptional: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-child", "--uuid-children")
]


# User

ArgUUIDUser: TypeAlias = Annotated[str, typer.Argument(help="User uuid.")]
FlagUUIDUserOptional: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--uuid-user",
        help="Transfer ownship of a collection to this UUID.",
    ),
]
FlagUUIDUsers: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-user", help="A required list of user UUIDs.")
]
FlagUUIDUsersOptional: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option("--uuid-user", help="An optional list of user UUIDs."),
]


# Documents

FlagUUIDDocuments: TypeAlias = Annotated[List[str], typer.Option("--uuid-document")]
FlagUUIDDocumentsOptional: TypeAlias = Annotated[
    Optional[List[str]], typer.Option("--uuid-document")
]
ArgUUIDDocument: TypeAlias = Annotated[str, typer.Argument()]
ArgUUIDCollection: TypeAlias = Annotated[str, typer.Argument()]

# Events

FlagUUIDEvent = Annotated[str, typer.Option("--uuid-event")]
FlagUUIDEventOptional = Annotated[Optional[str], typer.Option("--uuid-event")]

# --------------------------------------------------------------------------- #
# Field flags


FlagColumns: TypeAlias = Annotated[List[str], typer.Option("--column")]
FlagLevel: TypeAlias = Annotated[LevelStr, typer.Option("--level")]
FlagName = Annotated[Optional[str], typer.Option("--name")]
FlagDescription = Annotated[Optional[str], typer.Option("--description")]
FlagUrl = Annotated[Optional[str], typer.Option("--url")]
FlagUrlImage = Annotated[Optional[str], typer.Option("--url-image")]
FlagPublic = Annotated[bool, typer.Option("--public/--private")]
FlagPublicOptional = Annotated[Optional[bool], typer.Option("--public/--private")]
FlagRestore = Annotated[bool, typer.Option("--restore/--delete")]
FlagKindRecurse: TypeAlias = Annotated[KindRecurse, typer.Option("--recurse-strategy")]


# --------------------------------------------------------------------------- #
# Children flags

FlagChildrenUser: TypeAlias = Annotated[
    Optional[ChildrenUser], typer.Option("--child", "--children")
]
FlagChildrenCollection: TypeAlias = Annotated[
    ChildrenCollection, typer.Option("--child", "--children")
]
FlagChildrenDocument: TypeAlias = Annotated[
    ChildrenDocument, typer.Option("--child", "--children")
]


V = ParamSpec("V")
AsyncRequestCallable = Callable[V, Coroutine[httpx.Response, Any, Any]]
RequestCallable = Callable[V, httpx.Response]

from rich.table import Table


def print_table(
    res: httpx.Response,
    *,
    data=None,
    columns: FlagColumns = list(),
) -> None:
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

    print("columns", columns)
    keys = tuple(data[0].keys())
    if columns:
        keys = tuple(key for key in columns if keys)
    print("keys", keys)

    table.add_column("count")
    for count, key in enumerate(keys):
        table.add_column(
            key,
            style=typer.colors.BLUE if (count % 2) else typer.colors.BRIGHT_BLUE,
            justify="center",
        )

    if data:
        for count, item in enumerate(data):
            flat = tuple(str(item[key]) for key in keys)
            table.add_row(str(count), *flat)

    CONSOLE.print(table)


def print_json(res: httpx.Response, *, data=None) -> None:
    data = res.json() or data
    CONSOLE.print_json(json.dumps(data))


def print_result(
    res: httpx.Response,
    output: FlagOutput,
    *,
    columns: FlagColumns = list(),
    data=None,
) -> None:
    match output:
        case Output.json:
            print_json(res, data=data)
        case Output.table:
            print_table(res, data=data, columns=columns)


def handle_response(
    res: httpx.Response,
    output: FlagOutput,
    *,
    columns: FlagColumns = None,
    data=None,
) -> None:
    try:
        data = data if data is not None else res.json()
    except json.JSONDecodeError:
        data = None

    if 200 <= res.status_code < 300:
        print_result(res, output, data=data, columns=columns)
    else:
        CONSOLE.print(f"[red]Recieved bad status code `{res.status_code}`.")
        if data:
            CONSOLE.print("[red]" + json.dumps(data, indent=2))


class BaseRequests:
    """ """

    columns: List[str]
    output: Output | None
    token: str | None
    config: Config
    _client: httpx.AsyncClient | None
    commands: ClassVar[Tuple[str, ...]] = tuple()
    children: ClassVar[None | Tuple[Type[Self], ...]] = None

    @classmethod
    def from_(cls, v: "BaseRequests") -> Self:
        return cls(
            client=v._client,
            config=v.config,
            token=v.token,
        )

    def __init__(
        self,
        config: Config,
        client: httpx.AsyncClient | None = None,
        token: str | None = None,
    ):
        # self.typer = typer.Typer()
        self.token = token
        self.config = config
        self._client = client
        self.output = None
        self.columns = list()

    @functools.cached_property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            msg = "Client has was not provided to constructor or set."
            raise ValueError(msg)
        return self._client

    @property
    def headers(self):
        h = dict(
            content_type="application/json",
        )
        if self.token:
            h.update(authorization=f"bearer {self.token}")
        return h

    def callback(self, output: FlagOutput = Output.json, columns: FlagColumns = list()):
        """Specify request output format."""
        if output == Output.json and len(columns):
            CONSOLE.print("Cannot specify `--columns` with `--output=json`.")
            raise typer.Exit(1)

        if self.output is None:
            self.output = output

    @functools.cached_property
    def typer(self) -> typer.Typer:
        t: typer.Typer = typer.Typer(callback=self.callback)
        for cmd in self.commands:
            if Verbage._member_map_.get(cmd.split("_")[0]) is None:
                raise ValueError(f"Illegal verbage `{cmd}`.")

            fn = getattr(self, cmd, None)
            if fn is None:
                raise ValueError(f"No such attribute `{cmd}` of `{self}`.")
            decorated_cmd = self.request_to_cmd(fn)
            t.command(cmd.replace("_", "-"))(decorated_cmd)
        if self.children is None:
            return t

        for T in self.children:
            t.add_typer(
                T.from_(self).typer,
                name=RequestsEnum._value2member_map_[T].name,
            )

        return t

    def request_to_cmd(
        self,
        fn: AsyncRequestCallable,
    ) -> RequestCallable:
        """Decorated commands to make requests into usable (by typer)
        functions."""

        # Add the client.
        async def with_client_injected(
            *args: V.args,
            **kwargs: V.kwargs,
        ) -> httpx.Response:
            app = None
            if not self.config.remote:
                CONSOLE.print("[green]Using app instance in client.")
                from app.views import AppView

                app = AppView.view_router
            async with httpx.AsyncClient(
                app=app,
                base_url=self.config.host,
            ) as client:
                self.client = client
                self.token = self.config.defaults.token
                response = await fn(*args, **kwargs)
                handle_response(response, self.output, columns=self.columns)
                return response

        # Make sync
        @functools.wraps(fn)
        def wrapper(*args: V.args, **kwargs: V.kwargs) -> httpx.Response:
            return asyncio.run(with_client_injected(*args, **kwargs))

        return wrapper


class DocumentRequests(BaseRequests):
    commands = ("read",)

    async def read(
        self,
        document_ids: FlagUUIDDocuments = [],
    ) -> httpx.Response:
        url = "/documents"
        return await self.client.get(
            url,
            params=dict(document_ids=document_ids),
            headers=self.headers,
        )


class CollectionRequests(BaseRequests):
    commands = ("read", "create", "delete", "update")

    async def read(
        self,
        uuid_collection: ArgUUIDCollection,
        child: FlagChildrenCollection | None = None,
        uuid_child: FlagUUIDChildrenOptional = list(),
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
        name: FlagName = None,
        description: FlagDescription = None,
        public: FlagPublicOptional = None,
        uuid_document: FlagUUIDDocumentsOptional = list(),
    ) -> httpx.Response:
        return await self.client.post(
            "/collections",
            params=dict(uuid_document=uuid_document),
            json=dict(name=name, description=description, public=public),
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_collection: ArgUUIDCollection,
        restore: FlagRestore = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/collections/{uuid_collection}",
            params=dict(restore=restore),
            headers=self.headers,
        )

    async def update(
        self,
        uuid_collection: ArgUUIDCollection,
        name: FlagName = None,
        description: FlagDescription = None,
        public: FlagPublicOptional = None,
        uuid_user: FlagUUIDUserOptional = None,
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


class UserRequests(BaseRequests):
    commands = ("read", "update", "create", "delete")

    async def read(
        self,
        uuid_user: ArgUUIDUser,
        child: FlagChildrenUser = None,
        child_uuids: FlagUUIDChildrenOptional = list(),
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
        uuid_user: ArgUUIDUser,
        name: FlagName = None,
        description: FlagDescription = None,
        url: FlagUrl = None,
        url_image: FlagUrlImage = None,
        public: FlagPublic = None,
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
        self, uuid_user: ArgUUIDUser, restore: FlagRestore = False
    ) -> httpx.Response:
        return await self.client.delete(
            f"/users/{uuid_user}",
            params=dict(uuid_user=uuid_user, restore=restore),
            headers=self.headers,
        )


class AssignmentRequests(BaseRequests):
    commands = ("read", "create", "delete")

    async def read(
        self,
        uuid_collection: ArgUUIDCollection,
        uuid_document: FlagUUIDDocumentsOptional = list(),
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
        uuid_collection: ArgUUIDCollection,
        uuid_document: FlagUUIDDocuments,
        restore: FlagRestore = False,
    ):
        return await self.client.delete(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document, restore=restore),
            headers=self.headers,
        )

    async def create(
        self,
        uuid_collection: ArgUUIDCollection,
        uuid_document: FlagUUIDDocuments,
    ):
        return await self.client.post(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document),
            headers=self.headers,
        )


class GrantRequests(BaseRequests):
    commands = ("read_document", "read_user", "create", "delete")

    async def read_user(
        self,
        uuid_user: ArgUUIDUser,
        uuid_document: FlagUUIDDocumentsOptional = None,
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
        uuid_document: ArgUUIDDocument,
        uuid_user: FlagUUIDUsersOptional = None,
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
        uuid_document: ArgUUIDDocument,
        uuid_user: FlagUUIDUsers,
        level: FlagLevel = LevelStr.view,
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
        uuid_document: ArgUUIDDocument,
        uuid_user: FlagUUIDUsers,
        restore: FlagRestore = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/grants/documents/{uuid_document}",
            headers=self.headers,
            params=dict(uuid_user=uuid_user, restore=restore),
        )


ArgUUIDEvent: TypeAlias = Annotated[str, typer.Argument()]
FlagFlatten: TypeAlias = Annotated[
    bool,
    typer.Option(
        "--flatten/--heads",
        help="Return only heads (entries with no parents).",
    ),
]
FlagKind: TypeAlias = Annotated[
    Optional[KindEvent],
    typer.Option("--kind", "-k", help="Matches against the `kind` field."),
]
FlagKindObject: TypeAlias = Annotated[
    Optional[KindObject],
    typer.Option(
        "--object",
        "-j",
        help="Object kind, matches again the `kind_obj` field.",
    ),
]
FlagUUIDEventObject: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--uuid-object",
        "--uuid",
        help="Target object UUID.",
    ),
]


class EventsRequests(BaseRequests):
    commands = ("read", "search", "restore")
    columns = [
        "timestamp",
        "uuid_root",
        "uuid_parent",
        "uuid",
        "api_version",
        "api_origin",
        "kind",
        "kind_obj",
        "uuid_obj",
    ]

    def callback(
        self,
        output: FlagOutput = Output.table,
        columns: FlagColumns = list(),
    ):
        """Specify request output format."""
        self.output = output
        if not columns:
            self.columns = columns
        print(self.columns)

    async def read(
        self,
        uuid_event: ArgUUIDEvent,
    ) -> httpx.Response:
        return await self.client.get(
            f"/events/{uuid_event}",
            headers=self.headers,
            params=dict(uuid_user=uuid_event, tree=tree),
        )

    async def search(
        self,
        flatten: FlagFlatten = True,
        kind: FlagKind = None,
        kind_obj: FlagKindObject = None,
        uuid_obj: FlagUUIDEventObject = None,
        recurse: FlagKindRecurse = KindRecurse.depth_first,
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
        uuid_object: FlagUUIDEventObject = None,
        uuid_event: FlagUUIDEventOptional = None,
    ) -> httpx.Response:
        match [uuid_object is None, uuid_event is None]:
            case [True, True] | [False | False]:
                CONSOLE.print(
                    "Exactly one of `--uuid-object` and `--uuid-event` must be specified."
                )
                raise typer.Exit(1)
            case [True, _]:
                return await self.client.patch(
                    f"/events/{uuid_event}/objects", headers=self.headers
                )
            case [_, True]:
                return await self.client.patch(
                    f"/events/objects/{uuid_object}", headers=self.headers
                )


class RequestsEnum(enum.Enum):
    users = UserRequests
    collections = CollectionRequests
    documents = DocumentRequests
    grants = GrantRequests
    assignments = AssignmentRequests
    events = EventsRequests


class Requests(BaseRequests):
    commands = tuple()
    children = tuple(v.value for v in RequestsEnum)

    users: UserRequests
    collections: CollectionRequests
    documents: DocumentRequests
    grants: GrantRequests
    assignments: AssignmentRequests
    events: EventsRequests

    def __init__(
        self,
        config: Config,
        client: httpx.AsyncClient | None = None,
        token: str | None = None,
    ):
        super().__init__(config, client=client, token=token)
        for requester in RequestsEnum:
            setattr(
                self,
                requester.name,
                requester.value(config, client, token),
            )

    def update_token(self, token: str):
        self.token = token
        for ee in RequestsEnum:
            requester = getattr(self, ee.name)
            requester.token = token
