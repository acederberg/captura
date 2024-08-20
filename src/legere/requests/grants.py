# =========================================================================== #
from typing import ClassVar

import httpx
import typer

# --------------------------------------------------------------------------- #
from captura.models import LevelStr
from legere import flags
from legere.handlers import AssertionHandler
from legere.requests.base import BaseRequests, ContextData, methodize, params


# NOTE: For management of document grants. Notice the duality between the
#       command names. This will be put on document requests, so it will be
#       used like `client documents grants ...`.
class DocumentGrantRequests(BaseRequests):
    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        level: flags.FlagLevel = LevelStr.view,
        uuid_user: flags.FlagUUIDUsersOptional = None,
        pending: flags.FlagPending = False,
        pending_from: flags.FlagPendingFromOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(cls.fmt_url.format(uuid_document)),
            params=params(
                uuid_user=uuid_user,
                level=level.name,
                pending=pending,
                pending_from=pending_from.name if pending_from is not None else None,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_invite(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        level: flags.FlagLevel = LevelStr.view,
        uuid_user: flags.FlagUUIDUsersOptional = None,
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(cls.fmt_url.format(uuid_document)),
            params=params(uuid_user=uuid_user, level=level.name, force=force),
            headers=context.headers,
        )

    @classmethod
    def req_revoke(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_user: flags.FlagUUIDUsers,
        force: flags.FlagForce = False,
        pending: flags.FlagPending = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(cls.fmt_url.format(uuid_document)),
            headers=context.headers,
            params=dict(uuid_user=uuid_user, force=force, pending=pending),
        )

    @classmethod
    def req_approve(
        cls,
        _context: typer.Context,
        uuid_document: flags.ArgUUIDDocument,
        *,
        uuid_user: flags.FlagUUIDUsers,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url(cls.fmt_url.format(uuid_document)),
            params=params(uuid_user=uuid_user),
            headers=context.headers,
        )

    fmt_url: ClassVar[str] = "/grants/documents/{}"
    typer_check_verbage = False
    typer_commands = dict(
        read="req_read",
        invite="req_invite",
        revoke="req_revoke",
        approve="req_approve",
    )
    approve = methodize(req_approve, __func__=req_approve.__func__)  # type: ignore
    invite = methodize(req_invite, __func__=req_invite.__func__)  # type: ignore
    revoke = methodize(req_revoke, __func__=req_revoke.__func__)  # type: ignore
    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore


class UserGrantRequests(BaseRequests):
    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        level: LevelStr = LevelStr.view,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
        pending: flags.FlagPending = False,
        pending_from: flags.FlagPendingFromOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(cls.fmt_url.format(uuid_user)),
            params=params(
                level=level.name,
                uuid_document=uuid_document,
                pending=pending,
                pending_from=pending_from.name if pending_from is not None else None,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_accept(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url(cls.fmt_url.format(uuid_user)),
            params=params(uuid_document=uuid_document),
            headers=context.headers,
        )

    @classmethod
    def req_reject(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(cls.fmt_url.format(uuid_user)),
            params=params(
                uuid_document=uuid_document,
                force=force,
            ),
            headers=context.headers,
        )

    @classmethod
    def req_request(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        level: LevelStr = LevelStr.view,
        uuid_document: flags.FlagUUIDDocumentsOptional = None,
        force: flags.FlagForce = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url(cls.fmt_url.format(uuid_user)),
            params=params(
                level=level.name,
                uuid_document=uuid_document,
                force=force,
            ),
            headers=context.headers,
        )

    fmt_url: ClassVar[str] = "/grants/users/{}"
    typer_check_verbage = False
    typer_commands = dict(
        read="req_read",
        request="req_request",
        reject="req_reject",
        accept="req_accept",
    )

    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore
    request = methodize(req_request, __func__=req_request.__func__)  # type: ignore
    reject = methodize(req_reject, __func__=req_reject.__func__)  # type: ignore
    accept = methodize(req_accept, __func__=req_accept.__func__)  # type: ignore


class GrantRequests(BaseRequests):
    typer_children = dict(
        documents=DocumentGrantRequests,
        users=UserGrantRequests,
    )
    documents: DocumentGrantRequests
    users: UserGrantRequests

    def __init__(
        self,
        context: ContextData,
        client: httpx.AsyncClient,
        *,
        handler: AssertionHandler | None = None,
        handler_methodize: bool = True,
        documents: DocumentGrantRequests | None = None,
        users: UserGrantRequests | None = None,
    ):
        super().__init__(
            context,
            client,
            handler=handler,
            handler_methodize=handler_methodize,
        )
        self.documents = documents or DocumentGrantRequests.spawn_from(self)
        self.users = users or UserGrantRequests.spawn_from(self)

    @property
    def d(self) -> DocumentGrantRequests:
        return self.documents

    @property
    def u(self) -> UserGrantRequests:
        return self.users


__all__ = (
    "DocumentGrantRequests",
    "UserGrantRequests",
    "GrantRequests",
)


if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    from legere.requests.base import typerize

    grants = typerize(GrantRequests)
    grants()
