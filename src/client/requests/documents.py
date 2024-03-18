import httpx
import typer
from client import flags
from client.requests.assignments import DocumentAssignmentRequests
from client.requests.base import BaseRequests, ContextData, params
from client.requests.grants import DocumentGrantRequests


class DocumentRequests(BaseRequests):
    typer_commands = dict(read="req_read",
         search="req_search",
         delete="req_delete",
         update="req_update",
         create="req_create",
        )
    typer_children = dict(grants=DocumentGrantRequests, assignments=DocumentAssignmentRequests)

    @classmethod
    def req_delete(
        cls, _context: typer.Context, *, uuid_document: flags.ArgUUIDDocument
    ) -> httpx.Request:
        url = f"/documents/{uuid_document}"
        context = ContextData.resolve(_context)
        return httpx.Request("DELETE", url, headers=context.headers)

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        *,
        name: flags.FlagName,
        description: flags.FlagDescription,
        format: flags.FlagFormat,
        content: flags.FlagContent,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url("/documents"),
            json=dict(
                name=name,
                description=description,
                format=format,
                content=content,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_update(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        format: flags.FlagFormatOptional = None,
        content: flags.FlagContentOptional = None,
        message: flags.FlagMessageOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url ( f"/documents/{uuid_document}"),
            json=params(
                name=name,
                description=description,
                format=format,
                content=content,
                message=message,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_read(
        cls, _context: typer.Context, uuid_document: flags.ArgUUIDDocument
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        url = context.url(f"/documents/{uuid_document}")
        return httpx.Request("GET", url, headers=context.headers)

    @classmethod
    def req_search(
        cls,
        _context: typer.Context,
        *,
        limit: flags.FlagLimit = 10,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
    ):
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url("/documents"),
            params=params(
                limit=limit,
                name_like=name_like,
                description_like=description_like,
            ),
            headers=context.headers,
        )


__all__ = ("DocumentRequests",)

if __name__ == "__main__":
    from client.requests.base import typerize

    documents = typerize(DocumentRequests)
    documents()
