import httpx
from client import flags
from typing import Any, Dict
from client.requests.base import BaseRequest
from app.models import LevelStr


__all__ = ("GrantRequests",)


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
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/grants/documents/{uuid_document}",
            headers=self.headers,
            params=dict(uuid_user=uuid_user, force=force),
        )
