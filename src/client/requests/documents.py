import httpx
from client import flags
from client.requests.base import BaseRequest, params

__all__ = ("DocumentRequests",)


class DocumentRequests(BaseRequest):
    command = "documents"
    commands = ("read", "search", "delete", "update", "create")

    async def delete(self, uuid_document: flags.ArgUUIDDocument) -> httpx.Response:
        url = f"/documents/{uuid_document}"
        return await self.client.delete(url, headers=self.headers)

    async def create(
        self,
        name: flags.FlagName,
        description: flags.FlagDescription,
        format: flags.FlagFormat,
        content: flags.FlagContent,
    ) -> httpx.Response:
        return await self.client.post(
            "/documents",
            json=dict(
                name=name,
                description=description,
                format=format,
                content=content,
            ),
            headers=self.headers,
        )

    async def update(
        self,
        uuid_document: flags.ArgUUIDDocument,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        format: flags.FlagFormatOptional = None,
        content: flags.FlagContentOptional = None,
        message: flags.FlagMessageOptional = None,
    ) -> httpx.Response:
        url = f"/documents/{uuid_document}"
        return await self.client.patch(
            url,
            json=params(
                name=name,
                description=description,
                format=format,
                content=content,
                message=message,
            ),
            headers=self.headers,
        )

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
