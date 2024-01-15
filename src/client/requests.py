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
import typer
import yaml
from app.models import (
    ChildrenDocument,
    Level,
    ChildrenCollection,
    ChildrenUser,
    LevelStr,
    KindObject,
)
from app.schemas import UserUpdateSchema

from client.config import Config

# =========================================================================== #
# Typer Flags and Args.

# --------------------------------------------------------------------------- #
# UUID Flags and Arguments
# NOTE: Annotations should eventually include help.

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


# --------------------------------------------------------------------------- #
# Field flags

FlagLevel: TypeAlias = Annotated[LevelStr, typer.Option("--level")]
FlagName = Annotated[Optional[str], typer.Option("--name")]
FlagDescription = Annotated[Optional[str], typer.Option("--description")]
FlagUrl = Annotated[Optional[str], typer.Option("--url")]
FlagUrlImage = Annotated[Optional[str], typer.Option("--url-image")]
FlagPublic = Annotated[bool, typer.Option("--public/--private")]
FlagPublicOptional = Annotated[Optional[bool], typer.Option("--public/--private")]


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


def handle_response(response: httpx.Response) -> None:
    try:
        content = response.json()
    except json.JSONDecodeError:
        content = None

    if 200 <= response.status_code < 300:
        rich.print_json(json.dumps(content))
    else:
        rich.print(f"[red]Recieved bad status code `{response.status_code}`.")
        if content:
            rich.print("[red]" + json.dumps(content, indent=2))


class BaseRequests:
    """ """

    token: str | None
    config: Config
    client: httpx.AsyncClient
    commands: ClassVar[Tuple[str, ...]] = tuple()
    children: ClassVar[None | Tuple[Type[Self], ...]] = None

    @classmethod
    def from_(cls, v: "BaseRequests") -> Self:
        return cls(
            client=v.client,
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
        self.client = client

    @functools.cached_property
    def headers(self):
        h = dict(
            content_type="application/json",
        )
        if self.token:
            h.update(authorization=f"bearer {self.token}")
        return h

    @functools.cached_property
    def typer(self) -> typer.Typer:
        t: typer.Typer = typer.Typer()
        for cmd in self.commands:
            fn = getattr(self, cmd, None)
            if fn is None:
                raise ValueError(f"No such attribute `{cmd}` of `{self}`.")
            decorated_cmd = self.request_to_cmd(fn)
            t.command(cmd)(decorated_cmd)
        if self.children is None:
            return t

        for T in self.children:
            # print(T.__name__)
            # print(RequestsEnums._value2member_map_[T].name)
            t.add_typer(
                T.from_(self).typer,
                name=RequestsEnums._value2member_map_[T].name,
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
                typer.echo("[green]Using app instance in client.")
                from app.views import AppView

                app = AppView.view_router
            async with httpx.AsyncClient(
                app=app,
                base_url=self.config.host,
            ) as client:
                self.client = client
                self.token = self.config.defaults.token
                response = await fn(*args, **kwargs)
                handle_response(response)
                return response

        # Make sync
        @functools.wraps(fn)
        def wrapper(*args: V.args, **kwargs: V.kwargs) -> httpx.Response:
            return asyncio.run(with_client_injected(*args, **kwargs))

        return wrapper


class DocumentRequests(BaseRequests):
    commands = ("read",)

    async def read(self, document_ids: FlagUUIDDocuments = []) -> httpx.Response:
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
                rich.print(
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
    ) -> httpx.Response:
        return await self.client.delete(
            f"/collections/{uuid_collection}",
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
                rich.print(
                    "[red]`child_uuids` can only be specified when `child` is too."
                )
                raise typer.Exit(1)
            case [ChildrenUser.collections, _]:
                params["uuid_collection"] = child_uuids
            case [ChildrenUser.documents, _]:
                params["uuid_document"] = child_uuids
            case _:
                rich.print(
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
        self, uuid_user: ArgUUIDUser, restore: bool = False
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
    ):
        return await self.client.delete(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document),
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
    ) -> httpx.Response:
        return await self.client.delete(
            f"/grants/documents/{uuid_document}",
            headers=self.headers,
            params=dict(uuid_user=uuid_user),
        )


class RequestsEnums(enum.Enum):
    users = UserRequests
    collections = CollectionRequests
    documents = DocumentRequests
    grants = GrantRequests
    assignments = AssignmentRequests


class Requests(BaseRequests):
    commands = tuple()
    children = tuple(v.value for v in RequestsEnums)
