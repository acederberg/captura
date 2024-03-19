from typing import Any, Dict

import httpx
import typer
from app.models import ChildrenCollection
from client import flags
from client.handlers import CONSOLE
from client.requests.assignments import CollectionAssignmentRequests
from client.requests.base import BaseRequests, ContextData, params

__all__ = ("CollectionRequests",)


class CollectionRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
        delete="req_delete",
        update="req_update",
        search="req_search",
    )
    typer_children = dict(
        assignments=CollectionAssignmentRequests,
    )

    assignments: CollectionAssignmentRequests

    def __init__(self, context: ContextData, client: httpx.AsyncClient):
        super().__init__(context, client)
        self.assignments = CollectionAssignmentRequests.spawn_from(self)

    @classmethod
    def req_search(
        cls,
        _context: typer.Context,
        *,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url("/collections"),
            params=params(
                name_like=name_like,
                description_like=description_like,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        child: flags.FlagChildrenCollection | None = None,
        uuid_child: flags.FlagUUIDs = list(),
    ) -> httpx.Request:
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

        context = ContextData.resolve(_context)

        # Determine URL
        url_parts = ["collections", uuid_collection]
        if child is not None:
            url_parts.append(child)
        url = context.url("/" + "/".join(url_parts))
        return httpx.Request("GET", url, params=params, headers=context.headers)

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        public: flags.FlagPublicOptional = None,
        uuid_document: flags.FlagUUIDDocumentsOptional = list(),
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url("/collections"),
            params=dict(uuid_document=uuid_document),
            json=dict(name=name, description=description, public=public),
            headers=context.headers,
        )

    @classmethod
    def req_delete(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        force: flags.FlagForce = False,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(f"/collections/{uuid_collection}"),
            params=dict(force=force),
            headers=context.headers,
        )

    @classmethod
    def req_update(
        cls,
        _context: typer.Context,
        uuid_collection: flags.ArgUUIDCollection,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        public: flags.FlagPublicOptional = None,
        uuid_user: flags.FlagUUIDUserOptional = None,
    ) -> httpx.Request:
        data = params(
            name=name,
            description=description,
            public=public,
            uuid_user=uuid_user,
        )
        print(data)
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url(f"/collections/{uuid_collection}"),
            json=data,
            headers=context.headers,
        )

__all__ = ("DocumentRequests",)

if __name__ == "__main__":
    from client.requests.base import typerize
    collections = typerize(CollectionRequests)
    collections()

