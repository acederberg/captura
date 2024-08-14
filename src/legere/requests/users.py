# =========================================================================== #

# =========================================================================== #

import httpx
import typer

# --------------------------------------------------------------------------- #
from legere import flags
from legere.handlers import AssertionHandler
from legere.requests.base import BaseRequests, ContextData, methodize, params, typerize
from legere.requests.grants import UserGrantRequests


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

    @classmethod
    def req_update(
        cls,
        _context: typer.Context,
        uuid_user: flags.ArgUUIDUser,
        *,
        name: flags.FlagNameOptional = None,
        description: flags.FlagDescriptionOptional = None,
        content: flags.FlagContentOptional = None,
        url: flags.FlagUrlOptional = None,
        url_image: flags.FlagUrlImageOptional = None,
        public: flags.FlagPublicOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        json = dict(
            name=name,
            description=description,
            url=url,
            url_image=url_image,
            public=public,
            content=content,
        )
        return httpx.Request(
            "PATCH",
            context.url(f"/users/{uuid_user}"),
            json=json,
            headers=context.headers,
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
        self.grants = UserGrantRequests.spawn_from(self)

    @property
    def g(self) -> UserGrantRequests:
        return self.grants

    typer_commands = dict(
        read="req_read",
        search="req_search",
        update="req_update",
        delete="req_delete",
    )
    typer_children = {"grants": UserGrantRequests}

    grants: UserGrantRequests
    update = methodize(req_update, __func__=req_update.__func__)  # type: ignore
    delete = methodize(req_delete, __func__=req_delete.__func__)  # type: ignore
    search = methodize(req_search, __func__=req_search.__func__)  # type: ignore
    read = methodize(req_read, __func__=req_read.__func__)  # type: ignore


__all__ = ("UserRequests",)


if __name__ == "__main__":

    users = typerize(UserRequests)
    users()
