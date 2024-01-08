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
    TypeAlias,
)

import httpx
import rich
import typer
import yaml
from app.models import Level
from app.schemas import UserUpdateSchema

from client.config import Config


class UserChildEnum(str, enum.Enum):
    collections = "collections"
    documents = "documents"
    edits = "edits"


class UserLevelEnum(str, enum.Enum):
    view = "view"
    modify = "modify"
    own = "own"


FlagUUIDDocument: TypeAlias = Annotated[str, typer.Option("--uuid-document")]
FlagUUIDDocuments: TypeAlias = Annotated[List[str], typer.Option("--uuid-document")]
FlagUUIDDocumentsOptional: TypeAlias = Annotated[
    Optional[List[str]], typer.Option("--uuid-document")
]
FlagUUIDUser: TypeAlias = Annotated[str, typer.Option("--uuid-user")]
FlagUUIDUsers: TypeAlias = Annotated[List[str], typer.Option("--uuid-user")]
FlagUUIDUsersOptional: TypeAlias = Annotated[
    Optional[List[str]], typer.Option("--uuid-user")
]
FlagLevel: TypeAlias = Annotated[UserLevelEnum, typer.Option("--level")]
FlagName = Annotated[Optional[str], typer.Option("--name")]
FlagDescription = Annotated[Optional[str], typer.Option("--description")]
FlagUrl = Annotated[Optional[str], typer.Option("--url")]
FlagUrlImage = Annotated[Optional[str], typer.Option("--url-image")]
FlagPublic = Annotated[Optional[bool], typer.Option("--public")]
ArgUserChild: TypeAlias = Annotated[UserChildEnum, typer.Argument()]
ArgUUIDUser: TypeAlias = Annotated[str, typer.Argument()]
ArgUUIDDocument: TypeAlias = Annotated[str, typer.Argument()]


V = ParamSpec("V")
AsyncRequestCallable = Callable[V, Coroutine[httpx.Response, Any, Any]]
RequestCallable = Callable[V, httpx.Response]


def handle_response(response: httpx.Response) -> None:
    content = response.json()
    if 200 <= response.status_code < 300:
        rich.print_json(json.dumps(content))
    else:
        rich.print(f"[red]Recieved bad status code `{response.status_code}`.")
        rich.print("[red]" + json.dumps(content, indent=2))


class BaseRequests:
    """ """

    token: str | None
    config: Config
    client: httpx.AsyncClient
    commands: ClassVar[Tuple[str, ...]]

    def __init__(
        self,
        config: Config,
        client: httpx.AsyncClient | None = None,
        token: str | None = None,
    ):
        # self.typer = typer.Typer()
        self.token = token
        self.config = config
        if client is not None:
            self.client = client

    @property
    def headers(self):
        h = dict(
            content_type="application/json",
        )
        if self.token:
            h.update(authorization=f"bearer {self.token}")
        return h

    def typer(self) -> typer.Typer:
        t = typer.Typer()
        for cmd in self.commands:
            fn = getattr(self, cmd, None)
            if fn is None:
                raise ValueError(f"No such attribute `{cmd}` of `{self}`.")
            decorated_cmd = self.request_to_cmd(fn)
            t.command(cmd)(decorated_cmd)
        return t

    def request_to_cmd(
        self,
        fn: AsyncRequestCallable,
    ) -> RequestCallable:
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


class UserRequests(BaseRequests):
    commands = ("read", "read_child", "update", "create", "delete")

    async def read_child(self, child: ArgUserChild, uuid_user: ArgUUIDUser):
        url = f"/users/{uuid_user}/{child.value}"
        return await self.client.get(url, headers=self.headers)

    async def read(self, uuid_user: ArgUUIDUser):
        return await self.client.get(f"/users/{uuid_user}", headers=self.headers)

    async def update(
        self,
        uuid_user: FlagUUIDUser,
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
        level: FlagLevel = UserLevelEnum.view,
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
