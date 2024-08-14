import httpx
import typer

# --------------------------------------------------------------------------- #
from legere import flags
from legere.handlers import CONSOLE
from legere.requests.base import typerize

from .base import BaseRequests, ContextData, methodize, params


class TokenRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
        register="req_register",
    )

    @classmethod
    def req_register(
        cls,
        _context: typer.Context,
        *,
        email: flags.FlagEmail,
        name: flags.FlagName,
        description: flags.FlagDescription,
        url: flags.FlagUrlOptional = None,
        url_image: flags.FlagUrlImageOptional = None,
        public: flags.FlagPublic = True,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)

        return httpx.Request(
            "POST",
            context.url("/auth/register"),
            headers=context.headers,
            params=params(
                email=email,
                name=name,
                description=description,
                url=url,
                url_image=url_image,
                public=public,
            ),
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

        token_payload = dict(sub=uuid, permissions=permissions)
        return httpx.Request(
            "POST",
            context.url("/auth/token"),
            json=token_payload,
            headers=context.headers,
        )

    typer_check_verbage = False

    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore[attr-defined]
    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore[attr-defined]
    register = methodize(req_register, __func__=req_register.__func__)  # type: ignore[attr-defined]


__all__ = ("TokenRequests",)


if __name__ == "__main__":
    tokens = typerize(TokenRequests)
    tokens()
