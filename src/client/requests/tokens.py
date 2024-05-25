import httpx
import typer

# --------------------------------------------------------------------------- #
from app.auth import TokenPermissionTier
from client import flags
from client.handlers import CONSOLE
from client.requests.base import typerize

from .base import BaseRequests, ContextData, methodize, params


class TokenRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
    )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        # NOTE: now global.
        # token: flags.FlagTokenOptional = None,
    ) -> httpx.Request:
        """Verify current token (as specified by configuration) or, when
        provided, the token provided by `--token`."""

        context = ContextData.resolve(_context)
        token = context.token
        if token is None:
            CONSOLE.print("[red]No token to check.")
            raise typer.Exit(1)

        return httpx.Request(
            "GET",
            context.url("/auth/token"),
            params=params(data=token.get_secret_value()),
            headers=context.headers,
        )

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        uuid_user: flags.FlagUUIDUserOptional = None,
        admin: flags.FlagAdmin = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        if uuid_user is not None:
            uuid = uuid_user
        elif context.config.profile is not None:
            uuid = context.config.profile.uuid_user
        else:
            context.console_handler.console.print("[red]Could not determine uuid.")
            raise typer.Exit(1)

        permissions = list()
        if admin:
            permissions.append("tier:admin")

        token_payload = dict(uuid=uuid, permissions=permissions)
        return httpx.Request(
            "POST",
            context.url("/auth/token"),
            json=token_payload,
            headers=context.headers,
        )

    read = methodize(req_read, __func__=req_read.__func__)
    create = methodize(req_create, __func__=req_create.__func__)


__all__ = ("TokenRequests",)


if __name__ == "__main__":
    tokens = typerize(TokenRequests)
    tokens()
