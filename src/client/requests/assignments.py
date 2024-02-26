from typing import Any, Dict

import httpx
import typer
from client import flags
from client.requests.base import BaseRequest


class AssignmentCollectionRequests(BaseRequest):
    command = "collections"
    commands = ("read", "create", "delete")

    async def read(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
    ) -> httpx.Response:
        print("assign-collections-read", self.client)
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
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document, force=force),
            headers=self.headers,
        )

    async def create(
        self,
        uuid_collection: flags.ArgUUIDCollection,
        uuid_document: flags.FlagUUIDDocuments,
    ) -> httpx.Response:
        return await self.client.post(
            f"/assignments/collections/{uuid_collection}",
            params=dict(uuid_document=uuid_document),
            headers=self.headers,
        )


class AssignmentDocumentRequests(BaseRequest):
    command = "documents"
    commands = ("read", "create", "delete")

    async def read(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_collection: flags.FlagUUIDCollectionsOptional = list(),
    ) -> httpx.Response:
        params: Dict[str, Any] = dict()
        if uuid_collection:
            params.update(uuid_collection=uuid_collection)
        return await self.client.get(
            f"/assignments/documents/{uuid_document}",
            params=params,
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_collection: flags.FlagUUIDCollections,
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/assignments/documents/{uuid_document}",
            params=dict(uuid_collection=uuid_collection, force=force),
            headers=self.headers,
        )

    async def create(
        self,
        uuid_document: flags.ArgUUIDDocument,
        uuid_collection: flags.FlagUUIDCollections,
    ) -> httpx.Response:
        return await self.client.post(
            f"/assignments/documents/{uuid_document}",
            params=dict(uuid_collection=uuid_collection),
            headers=self.headers,
        )


class AssignmentRequests(BaseRequest):
    command = "assignments"
    children = (AssignmentCollectionRequests, AssignmentDocumentRequests)

    collections: AssignmentCollectionRequests
    documents: AssignmentDocumentRequests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.documents = AssignmentDocumentRequests.from_(self)
        self.collections = AssignmentCollectionRequests.from_(self)
