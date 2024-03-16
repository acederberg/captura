import httpx
import typer
from client import flags
from client.config import ProfileConfig
from client.handlers import CONSOLE

from .base import BaseRequest, ContextData, params


class TokenRequests(BaseRequest):

    typer_commands = dict(
        read="req_read",
        create="req_create",
    )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        token: flags.FlagTokenOptional = None,
    ) -> httpx.Request:
        """Verify current token (as specified by configuration) or, when
        provided, the token provided by `--token`."""

        context = ContextData.resolve(_context)
        token = token if token is not None else context.config.token
        if token is None:
            CONSOLE.print("[red]No token to check.")
            raise typer.Exit(1)

        return httpx.Request(
            "GET",
            context.url("/auth/token"),
            params=params(data=token),
            headers=context.headers,
        )

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        uuid_user: flags.FlagUUIDUserOptional = None,
        admin: flags.FlagAdmin = None,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        uuid = uuid_user if uuid_user is not None else context.config.profile
        if not uuid:
            raise ValueError("Profile not set.")

        token_payload = dict(uuid=uuid, admin=admin)
        return httpx.Request(
            "POST",
            context.url("/auth/token"),
            json=token_payload,
            headers=context.headers,
        )

__all__ = ("TokenRequests",)


if __name__ == "__main__":
    from client.requests.base import typerize
    tokens = typerize(TokenRequests)
    tokens()
