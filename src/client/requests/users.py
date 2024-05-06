# =========================================================================== #

# =========================================================================== #
from typing import Optional

import httpx
import rich
import typer

# --------------------------------------------------------------------------- #
from client import flags
from client.requests.base import BaseRequests, ContextData, methodize, params
from client.requests.grants import UserGrantRequests


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
        randomize: bool = True,
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
                uuids=uuids,
                limit=limit,
                name_like=name_like,
                description_like=description_like,
                include_public=include_public,
                randomize=randomize,
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
            context.url("/users"),
            headers=context.headers,
            json=dict(
                email=email,
                name=name,
                description=description,
                url=url,
                url_image=url_image,
                public=public,
            ),
        )

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
    typer_children = {"grants": UserGrantRequests}

    grants: UserGrantRequests
    update = methodize(req_update, __func__=req_update.__func__)  # type: ignore
    create = methodize(req_create, __func__=req_create.__func__)  # type: ignore
    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore

    def __init__(self, context: ContextData, client: httpx.AsyncClient):
        super().__init__(context, client)
        self.grants = UserGrantRequests.spawn_from(self)


__all__ = ("UserRequests", "DemoRequests")


if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
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
