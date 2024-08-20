import httpx
import typer

# --------------------------------------------------------------------------- #
from legere import flags
from legere.handlers import AssertionHandler
from legere.requests.assignments import DocumentAssignmentRequests
from legere.requests.base import BaseRequests, ContextData, methodize, params
from legere.requests.grants import DocumentGrantRequests


class DocumentRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        # search="req_search",
        delete="req_delete",
        update="req_update",
        create="req_create",
    )
    typer_children = dict(
        grants=DocumentGrantRequests,
        assignments=DocumentAssignmentRequests,
    )
    grants: DocumentGrantRequests
    assignments: DocumentAssignmentRequests

    def __init__(
        self,
        context: ContextData,
        client: httpx.AsyncClient,
        *,
        handler: AssertionHandler | None = None,
        handler_methodize: bool = False,
    ):
        super().__init__(
            context,
            client,
            handler=handler,
            handler_methodize=handler_methodize,
        )
        self.grants = DocumentGrantRequests.spawn_from(self)
        self.assignments = DocumentAssignmentRequests.spawn_from(self)

    @property
    def g(self) -> DocumentGrantRequests:
        return self.grants

    @property
    def a(self) -> DocumentAssignmentRequests:
        return self.assignments

    @classmethod
    def req_delete(
        cls, _context: typer.Context, uuid_document: flags.ArgUUIDDocument
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        url = context.url(f"/documents/{uuid_document}")
        return httpx.Request("DELETE", url, headers=context.headers)

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        *,
        name: flags.FlagName,
        description: flags.FlagDescription,
        content: flags.FlagContentOptional = None,
        public: flags.FlagPublic = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url("/documents"),
            json=dict(
                name=name,
                description=description,
                content=content,
                public=public,
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
        content: flags.FlagContentOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url(f"/documents/{uuid_document}"),
            json=params(
                name=name,
                description=description,
                content=content,
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

    # @classmethod
    # def req_search(
    #     cls,
    #     _context: typer.Context,
    #     *,
    #     limit: flags.FlagLimit = 10,
    #     name_like: flags.FlagNameLike = None,
    #     description_like: flags.FlagDescriptionLike = None,
    # ):
    #     context = ContextData.resolve(_context)
    #     return httpx.Request(
    #         "GET",
    #         context.url("/documents"),
    #         params=params(
    #             limit=limit,
    #             name_like=name_like,
    #             description_like=description_like,
    #         ),
    #         headers=context.headers,
    #     )

    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore
    update = methodize(req_update, __func__=req_update.__func__)  # type: ignore
    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore
    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore
    # search = methodize(req_search, __func__=req_search.__func__)  # type: ignore


__all__ = ("DocumentRequests",)

if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    from legere.requests.base import typerize

    documents = typerize(DocumentRequests)
    documents()
