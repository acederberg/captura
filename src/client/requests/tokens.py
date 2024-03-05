import httpx
import typer
from client import flags
from client.config import ProfileConfig
from client.handlers import CONSOLE

from .base import BaseRequest, params


class TokenRequests(BaseRequest):

    command = "token"
    commands = ("read", "create")

    @property
    def uuid_user(self) -> ProfileConfig:
        if self.config.profile is None:
            raise ValueError("Profile is not set.")
        return self.config.profile  # type: ignore

    async def read(
        self,
        token: flags.FlagTokenOptional = None,
    ) -> httpx.Response:
        """Verify current token (as specified by configuration) or, when
        provided, the token provided by `--token`."""

        token = token if token is not None else self.token
        if token is None:
            CONSOLE.print("[red]No token to check.")
            raise typer.Exit(1)

        return await self.client.get(
            "/auth/token",
            params=params(data=token),
            headers=self.headers,
        )

    async def create(
        self, 
        uuid_user: flags.FlagUUIDUserOptional = None,
        admin: flags.FlagAdmin = None,
    ) -> httpx.Response:
        uuid = uuid_user if uuid_user is not None else self.uuid_user
        token_payload = dict(uuid=uuid, admin=admin)
        return await self.client.post(
            "/auth/token",
            json=token_payload,
            headers=self.headers,
        )
