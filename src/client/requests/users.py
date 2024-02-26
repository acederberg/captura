from typing import Optional

import httpx
import typer
import yaml
from app.models import ChildrenUser
from client import flags
from client.config import ProfileConfig
from client.handlers import CONSOLE
from client.requests.base import BaseRequest, params


class DemoRequests(BaseRequest):
    command = "demo"
    commands = ("read", "create", "activate",)

    async def read(
        self,
        *,
        invitation_uuid: flags.FlagUUIDUserOptional = None,
        invitation_code: flags.FlagInvitationCodesOptional = None,
        invitation_email: flags.FlagInvitationEmailsOptional = None,
    ) -> httpx.Response:
        return await self.client.get(
            "/users/extensions/demos",
            params=params(
                invitation_code=invitation_code,
                invitation_uuid=invitation_uuid,
                invitation_email=invitation_email,
            ),
            headers=self.headers,
        )

    async def create(
        self,
        *,
        invitation_email: flags.FlagInvitationEmail,
        name: flags.FlagName,
        description: flags.FlagDescription,
        url: flags.FlagUrl = None,
        url_image: flags.FlagUrlImage = None,
        public: flags.FlagPublic = True,
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        json_data = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
        )
        return await self.client.post(
            "/users/extensions/demos",
            json=json_data,
            params=params(invitation_email=invitation_email,
                          force=force),
            headers=self.headers,
        )

    async def activate(
        self,
        *,
        invitation_uuid: flags.ArgUUIDUser,
        invitation_code: flags.FlagInvitationCode,
        invitation_email: flags.FlagInvitationEmail,
    ) -> httpx.Response:
        return await self.client.patch(
            f"/users/extensions/demos/{invitation_uuid}",
            params=dict(
                invitation_uuid=invitation_uuid,
                invitation_code=invitation_code,
                invitation_email=invitation_email,
            ),
            headers=self.headers,
        )


class UserRequests(BaseRequest):
    command = "users"
    commands = ("read", "search", "update", "create", "delete")
    children = DemoRequests,

    async def search(
        self,
        child: flags.FlagChildrenUser = None,
        uuid_user: Optional[str] = None,
        uuids: flags.FlagUUIDs = None,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
        limit: flags.FlagLimit = 10,
        include_public: flags.FlagIncludePublic = True,
    ):
        if uuid_user is None:
            uuid_user = self.config.profile.uuid_user # type: ignore

        child_name = child.name if child is not None else "users"
        return await self.client.get(
            f"/users/{uuid_user}/{child_name}",
            headers=self.headers,
            params=params(
                uuid=uuids,
                limit=limit, 
                name_like=name_like,
                description_like=description_like,
                include_public=include_public,
            ),
        )

    async def read(
        self,
        uuid_user: flags.ArgUUIDUser
    ) -> httpx.Response:
        return await self.client.get(
            f"/users/{uuid_user}",
            headers=self.headers,
        )

    async def update(
        self,
        uuid_user: flags.ArgUUIDUser,
        name: flags.FlagName = None,
        description: flags.FlagDescription = None,
        url: flags.FlagUrl = None,
        url_image: flags.FlagUrlImage = None,
        public: flags.FlagPublic = None,
    ) -> httpx.Response:
        params = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
        )
        params = {k: v for k, v in params.items() if v is not None}
        return await self.client.patch(
            f"/users/{uuid_user}",
            params=params,
            headers=self.headers,
        )

    async def create(
        self,
        *,
        name: flags.FlagName = None,
        description: flags.FlagDescription = None,
        url: flags.FlagUrl = None,
        url_image: flags.FlagUrlImage = None,
        public: flags.FlagPublic = True,
    ) -> httpx.Response:
        json_data = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
        )
        # if filepath is not None:
        #     with open(filepath, "r") as file:
        #         json_data_file = yaml.safe_load(file)
        #     json_data_file.update(params)
        #     json_data = json_data_file

        return await self.client.post(
            "/users",
            json=json_data,
            headers=self.headers,
        )

    async def delete(
        self,
        uuid_user: flags.ArgUUIDUser,
        force: flags.FlagForce = False,
    ) -> httpx.Response:
        return await self.client.delete(
            f"/users/{uuid_user}",
            params=dict(
                uuid_user=uuid_user,
                force=force,
            ),
            headers=self.headers,
        )

__all__ = ("UserRequests", "DemoRequests")

