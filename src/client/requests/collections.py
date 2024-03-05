from typing import Any, Dict

import httpx
import typer
from app.models import ChildrenCollection
from client import flags
from client.handlers import CONSOLE
from client.requests.base import BaseRequest, params

__all__ = ("CollectionRequests",)


class CollectionRequests(BaseRequest):
    command = "collections"
    commands = ("read", "create", "delete", "update", "search")

    async def search(
        self,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
    ) -> httpx.Response:
        return await self.client.get(
            "/collections",
            params=params(
                name_like=name_like,
                description_like=description_like,
            ),
            headers=self.headers,
        )

    async def read(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        child: flags.FlagChildrenCollection | None = None,
        uuid_child: flags.FlagUUIDs = list(),
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
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
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
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/collections/{uuid_collection}",
            params=dict(force=force),
            headers=self.headers,
        )

    async def update(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        public: flags.FlagPublicOptional = None,
        uuid_user: flags.FlagUUIDUserOptional = None,
    ) -> httpx.Response:
        data = params(
            name=name,
            description=description,
            public=public,
            uuid_user=uuid_user,
        )
        return await self.client.patch(
            f"/collections/{uuid_collection}",
            json=data,
            headers=self.headers,
        )
