import httpx
import yaml
from client import flags
from client.requests.base import BaseRequest, params
from client.handlers import CONSOLE
import typer
from app.models import ChildrenUser


__all__ = ("UserRequests",)


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
        self, uuid_user: flags.ArgUUIDUser, force: flags.FlagForce = False
    ) -> httpx.Response:
        return await self.client.delete(
            f"/users/{uuid_user}",
            params=dict(uuid_user=uuid_user, force=force),
            headers=self.headers,
        )
