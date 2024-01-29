import httpx
from client.requests.base import BaseRequest, params
from client import flags

__all__ = ("DocumentRequests",)


class DocumentRequests(BaseRequest):
    command = "documents"
    commands = ("read", "search", "delete")

    async def delete(self, uuid_document: flags.ArgUUIDDocument) -> httpx.Response:
        url = f"/documents/{uuid_document}"
        return await self.client.delete(url, headers=self.headers)

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
