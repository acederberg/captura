from typing import Optional

import httpx
import rich
import typer
import yaml
from app.models import ChildrenUser
from client import flags
from client.config import ProfileConfig
from client.handlers import CONSOLE
from client.requests.base import BaseRequests, ContextData, methodize, params
from client.requests.grants import UserGrantRequests
from fastapi import Request


class DemoRequests(BaseRequests):
    typer_commands = dict(
        read="req_read",
        create="req_create",
        activate="req_activate",
    )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        *,
        invitation_uuid: flags.FlagUUIDUserOptional = None,
        invitation_code: flags.FlagInvitationCodesOptional = None,
        invitation_email: flags.FlagInvitationEmailsOptional = None,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            url=context.url("/users/extensions/demos"),
            params=params(
                invitation_code=invitation_code,
                invitation_uuid=invitation_uuid,
                invitation_email=invitation_email,
            ),
            headers=context.headers,
        )

    read = methodize(req_read, __func__=req_read.__func__)

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        *,
        invitation_email: flags.FlagInvitationEmail,
        name: flags.FlagNameOptional,
        description: flags.FlagDescriptionOptional,
        url: flags.FlagUrlOptional = None,
        url_image: flags.FlagUrlImageOptional = None,
        public: flags.FlagPublic = True,
        force: flags.FlagForce = False,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "POST",
            context.url("/users/extensions/demos"),
            json=dict(
                name=name,
                description=description,
                url=url,
                url_image=url_image,
                public=public,
            ),
            params=params(invitation_email=invitation_email, force=force),
            headers=context.headers,
        )

    create = methodize(req_read, __func__=req_read.__func__)

    @classmethod
    def req_activate(
        cls,
        _context: typer.Context,
        *,
        invitation_uuid: flags.ArgUUIDUser,
        invitation_code: flags.FlagInvitationCode,
        invitation_email: flags.FlagInvitationEmail,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "PATCH",
            context.url(f"/users/extensions/demos/{invitation_uuid}"),
            params=dict(
                invitation_uuid=invitation_uuid,
                invitation_code=invitation_code,
                invitation_email=invitation_email,
            ),
            headers=context.headers,
        )

    activate = methodize(req_activate, __func__=req_activate.__func__)


class UserRequests(BaseRequests):
    @classmethod
    def req_search(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        child: flags.FlagChildrenUser = None,
        uuids: flags.FlagUUIDs = None,
        name_like: flags.FlagNameLike = None,
        description_like: flags.FlagDescriptionLike = None,
        limit: flags.FlagLimit = 10,
        include_public: flags.FlagIncludePublic = True,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)

        #
        # if uuid_user is None:
        #     uuid_user = context.config.profile.uuid_user  # type: ignore

        child_name = child.name if child is not None else "users"
        return httpx.Request(
            "GET",
            context.url(f"/users/{uuid_user}/{child_name}"),
            headers=context.headers,
            params=params(
                uuid=uuids,
                limit=limit,
                name_like=name_like,
                description_like=description_like,
                include_public=include_public,
            ),
        )

    search = methodize(req_search, __func__=req_search.__func__)

    @classmethod
    def req_read(
        cls, _context: typer.Context, uuid_user: flags.ArgUUIDUser
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(f"/users/{uuid_user}"),
            headers=context.headers,
        )

    read = methodize(req_read, __func__=req_read.__func__)

    @classmethod
    def req_update(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        url: flags.FlagUrlOptional = None,
        url_image: flags.FlagUrlImageOptional = None,
        public: flags.FlagPublic = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        json = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
        )
        return httpx.Request(
            "PATCH",
            context.url(f"/users/{uuid_user}"),
            json=json,
            headers=context.headers,
        )

    @classmethod
    def req_create(
        cls,
        _context: typer.Context,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        url: flags.FlagUrlOptional = None,
        url_image: flags.FlagUrlImageOptional = None,
        public: flags.FlagPublic = True,
    ) -> httpx.Request:

        # context = ContextData.resolve(_context)
        # json_data = dict(
        #     name=name,
        #     description=description,
        #     url=url,
        #     url_image=url_image,
        #     public=public,
        # )
        rich.print("[red]Not implemented.")
        raise typer.Exit(1)

    @classmethod
    def req_delete(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        force: flags.FlagForce = False,
    ) -> httpx.Request:

        context = ContextData.resolve(_context)
        return httpx.Request(
            "DELETE",
            context.url(f"/users/{uuid_user}"),
            params=dict(
                uuid_user=uuid_user,
                force=force,
            ),
            headers=context.headers,
        )

    typer_commands = dict(
        read="req_read",
        search="req_search",
        update="req_update",
        create="req_create",
        delete="req_delete",
    )
    typer_children = {
        "demos": DemoRequests,
        "grants": UserGrantRequests,
    }

    demos: DemoRequests
    grants: UserGrantRequests
    update = methodize(req_update, __func__=req_update.__func__)  # type: ignore
    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore
    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore

    def __init__(self, context: ContextData, client: httpx.AsyncClient):
        super().__init__(context, client)
        self.demos = DemoRequests.spawn_from(self)
        self.grants = UserGrantRequests.spawn_from(self)


__all__ = ("UserRequests", "DemoRequests")


if __name__ == "__main__":
    from client.requests.base import typerize

    users = typerize(UserRequests)
    users()

# from app.schemas import mwargs
# from client.config import Config
# from client.handlers import ConsoleHandler
#
#
# async def main():
#     context = ContextData(config=Config(), console_handler=mwargs(ConsoleHandler))
#     async with httpx.AsyncClient() as client:
#
#         u = DemoRequests(context=context, client=client)
#         res = await u.read()
#         print("HERE", res)
#
# import asyncio
#
# asyncio.run(main())
