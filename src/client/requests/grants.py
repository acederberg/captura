from typing import Any, ClassVar, Dict

import httpx
from app.models import LevelStr
from client import flags
from client.requests.base import BaseRequest, params

__all__ = ("DocumentGrantRequests", "UserGrantRequests",)


# NOTE: For management of document grants. Notice the duality between the
#       command names. This will be put on document requests, so it will be
#       used like `client documents grants ...`.
class DocumentGrantRequests(BaseRequest):
    fmt_url: ClassVar[str] = "/grants/documents/{}"
    commands_check_verbage = False
    command = "grants"
    commands = ("read", "invite", "revoke", "approve")

    async def read(
        self,
        uuid_document: flags.ArgUUIDDocument,
        level: flags.FlagLevel = LevelStr.view,
        uuid_user: flags.FlagUUIDUsersOptional = None,
        pending: flags.FlagPending = False,
    ) -> httpx.Response:
        return await self.client.get(
            self.fmt_url.format(uuid_document),
            params=params(
                uuid_user=uuid_user, 
                level=level.name, 
                pending=pending
            ),
            headers=self.headers,
        )

    async def invite(
        self,
        uuid_document: flags.ArgUUIDDocument,
        level: flags.FlagLevel = LevelStr.view,
        uuid_user: flags.FlagUUIDUsersOptional = None,
    ) -> httpx.Response:
        return await self.client.post(
            self.fmt_url.format(uuid_document),
            params=params(uuid_user=uuid_user, level=level.name),
            headers=self.headers,
        )

    async def revoke(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_user: flags.FlagUUIDUsers,
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            self.fmt_url.format(uuid_document),
            headers=self.headers,
            params=dict(uuid_user=uuid_user, force=force),
        )

    async def approve(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_user: flags.FlagUUIDUsers,
    ) -> httpx.Response:
        return await self.client.patch(
            self.fmt_url.format(uuid_document),
            params=params(uuid_user=uuid_user),
        )


class UserGrantRequests(BaseRequest):
    fmt_url: ClassVar[str] = "/grants/users/{}"
    commands_check_verbage = False
    command = "grants"
    commands = ("read", "request", "reject", "accept")

    async def read(
        self,
        uuid_user: flags.ArgUUIDUser,
        level: LevelStr = LevelStr.view,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
        pending: flags.FlagPending = False,
    ) -> httpx.Response:
        return await self.client.get(
            self.fmt_url.format(uuid_user),
            params=params(
                level=level.name,
                uuid_document=uuid_document,
                pending=pending,
            ),
            headers=self.headers,
        )

    async def accept(
        self,
        uuid_user: flags.ArgUUIDUser,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
    ) -> httpx.Response:
        return await self.client.patch(
            self.fmt_url.format(uuid_user),
            params=params(uuid_document=uuid_document),
            headers=self.headers,
        )

    async def reject(
        self,
        uuid_user: flags.ArgUUIDUser,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            self.fmt_url.format(uuid_user),
            params=params(
                uuid_document=uuid_document,
                force=force,
            ),
            headers=self.headers,
        )

    async def request(
        self,
        uuid_user: flags.ArgUUIDUser,
        level: LevelStr = LevelStr.view,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
    ) -> httpx.Response:
        return await self.client.post(
            self.fmt_url.format(uuid_user),
            params=params(
                level=level.name,
                uuid_document=uuid_document,
            ),
            headers=self.headers,
        )
