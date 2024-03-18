from typing import Any, Dict

import httpx
import typer
from client import flags
from client.requests.base import BaseRequests, ContextData


class CollectionAssignmentRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
        delete="req_delete",
    )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        params: Dict[str, Any] = dict()
        if uuid_document:
            params.update(uuid_document=uuid_document)
        return httpx.Request(
            "GET",
            context.url(f"/assignments/collections/{uuid_collection}"),
            params=params,
            headers=context.headers,
        )

    @classmethod
    def req_delete(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        uuid_document: flags.FlagUUIDDocuments,
        force: flags.FlagForce = False,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(f"/assignments/collections/{uuid_collection}"),
            params=dict(uuid_document=uuid_document, force=force),
            headers=context.headers,
        )

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        uuid_document: flags.FlagUUIDDocuments,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(f"/assignments/collections/{uuid_collection}"),
            params=dict(uuid_document=uuid_document),
            headers=context.headers,
        )


class DocumentAssignmentRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
        delete="req_delete",
    )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_collection: flags.FlagUUIDCollectionsOptional = list(),
    ) -> httpx.Request:
        params: Dict[str, Any] = dict()
        if uuid_collection:
            params.update(uuid_collection=uuid_collection)
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(f"/assignments/documents/{uuid_document}"),
            params=params,
            headers=context.headers,
        )

    @classmethod
    def req_delete(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_collection: flags.FlagUUIDCollections,
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(f"/assignments/documents/{uuid_document}"),
            params=dict(uuid_collection=uuid_collection, force=force),
            headers=context.headers,
        )

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_collection: flags.FlagUUIDCollections,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(f"/assignments/documents/{uuid_document}"),
            params=dict(uuid_collection=uuid_collection),
            headers=context.headers,
        )


class AssignmentRequests(BaseRequests):
    typer_children = dict(collections=CollectionAssignmentRequests, documents=DocumentAssignmentRequests,)

    collections: CollectionAssignmentRequests
    documents: DocumentAssignmentRequests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.documents = DocumentAssignmentRequests.spawn_from(self)
        self.collections = CollectionAssignmentRequests.spawn_from(self)


__all__ = ("CollectionAssignmentRequests", "DocumentAssignmentRequests", "AssignmentRequests")


if __name__ == "__main__":
    from client.requests.base import typerize
    assignments = typerize(AssignmentRequests)
    assignments()
