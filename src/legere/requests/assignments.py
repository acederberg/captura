# =========================================================================== #

import httpx
import typer

# --------------------------------------------------------------------------- #
from legere import flags
from legere.requests.base import BaseRequests, ContextData, methodize, params


class CollectionAssignmentRequests(BaseRequests):
    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
        limit: flags.FlagLimitOptional = None,
        randomize: bool = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(f"/assignments/collections/{uuid_collection}"),
            params=params(
                uuid_document=uuid_document,
                limit=limit,
                randomize=randomize,
            ),
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
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(f"/assignments/collections/{uuid_collection}"),
            params=dict(uuid_document=uuid_document, force=force),
            headers=context.headers,
        )

    typer_commands = dict(
        read="req_read",
        create="req_create",
        delete="req_delete",
    )

    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore
    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore
    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore


class DocumentAssignmentRequests(BaseRequests):
    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_collection: flags.FlagUUIDCollectionsOptional = list(),
        limit: flags.FlagLimitOptional = None,
        randomize: bool = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(f"/assignments/documents/{uuid_document}"),
            params=params(
                uuid_collection=uuid_collection,
                limit=limit,
                randomize=randomize,
            ),
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
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(f"/assignments/documents/{uuid_document}"),
            params=dict(uuid_collection=uuid_collection, force=force),
            headers=context.headers,
        )

    typer_commands = dict(
        read="req_read",
        create="req_create",
        delete="req_delete",
    )

    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore
    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore
    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore


class AssignmentRequests(BaseRequests):
    typer_children = dict(
        collections=CollectionAssignmentRequests,
        documents=DocumentAssignmentRequests,
    )

    collections: CollectionAssignmentRequests
    documents: DocumentAssignmentRequests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.documents = DocumentAssignmentRequests.spawn_from(self)
        self.collections = CollectionAssignmentRequests.spawn_from(self)

    @property
    def c(self) -> CollectionAssignmentRequests:
        return self.collections

    @property
    def d(self) -> DocumentAssignmentRequests:
        return self.documents


__all__ = (
    "CollectionAssignmentRequests",
    "DocumentAssignmentRequests",
    "AssignmentRequests",
)


if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    from legere.requests.base import typerize

    assignments = typerize(AssignmentRequests)
    assignments()
