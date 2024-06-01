# =========================================================================== #
import hashlib
import secrets
from datetime import datetime
from typing import Annotated, List, Set, Tuple
from uuid import uuid4

from fastapi import Body, Depends, HTTPException, Query
from pydantic import TypeAdapter
from sqlalchemy import select

# --------------------------------------------------------------------------- #
from app import __version__, util
from app.auth import TokenPermissionTier
from app.config import Config
from app.controllers.base import Data, ResolvedUser
from app.depends import (
    DependsAccess,
    DependsConfig,
    DependsCreate,
    DependsDelete,
    DependsRead,
    DependsToken,
    DependsTokenOptional,
    DependsUpdate,
)
from app.err import ErrAccessUser, ErrDetail
from app.models import Collection, Document, Event, KindEvent, KindObject, User
from app.schemas import (
    AsOutput,
    CollectionMetadataSchema,
    CollectionSearchSchema,
    DocumentMetadataSchema,
    DocumentSearchSchema,
    EventSchema,
    OutputWithEvents,
    UserCreateSchema,
    UserExtraSchema,
    UserSchema,
    UserSearchSchema,
    UserUpdateSchema,
    mwargs,
)
from app.views import args
from app.views.base import (
    BaseView,
    OpenApiResponseCommon,
    OpenApiResponseUnauthorized,
    OpenApiTags,
)

logger = util.get_logger(__name__)

OpenApiResponseUser = {
    **OpenApiResponseCommon,
    403: {
        "model": ErrDetail[ErrAccessUser],
        "description": (
            "User must be logged in as the user specified in the url "
            "or an admin to not raise this status."
        ),
    },
}


def user(access: DependsAccess, uuid_user: args.PathUUIDUser) -> User:
    return access.user(uuid_user, exclude_public=True)


DependsUser = Annotated[User, Depends(user)]


class UserSearchView(BaseView):
    """Separate from :class:`UserView` so that it is clear that this is the
    sole batch of endpoints through which ``search`` style results are
    available. All other controllers should only support get by ``uuid``(s).
    """

    view_routes = dict(
        get_search_users=dict(
            name="Search Users",
            url="/{uuid_user}/users",
            #   ^^^^^^^^^^^^^^^^^^^^^  Search results ALWAYS scoped for users
            #   by uuid (since admins might need to simulate search results of
            #   other users).
        ),
        get_search_documents=dict(
            url="/{uuid_user}/documents",
            name="Search User Documents",
        ),
        get_search_collections=dict(
            url="/{uuid_user}/collections",
            name="Search User Collections",
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.users],
        responses=OpenApiResponseUser,
    )

    # ----------------------------------------------------------------------- #

    # NOTE: This includes the path parameter so that admins may simulate
    #       exactly the search results of another user.
    @classmethod
    def get_search_users(
        cls,
        user: DependsUser,
        read: DependsRead,
        param: Annotated[UserSearchSchema, Depends()],
    ) -> AsOutput[List[UserSchema]]:
        """Get user collaborators or just list some users."""

        res: List[User] = read.search_user(user, param)
        return mwargs(
            AsOutput[List[UserSchema]],
            data=TypeAdapter(List[UserSchema]).validate_python(res),
        )

    # TODO: Test that users cannot access private docs/colls of others here.
    @classmethod
    def get_search_documents(
        cls,
        user: DependsUser,
        read: DependsRead,
        param: DocumentSearchSchema = Depends(),
    ) -> AsOutput[List[DocumentMetadataSchema]]:
        res: List[Document] = read.search_user(user, param)
        return mwargs(
            AsOutput[List[DocumentMetadataSchema]],
            data=TypeAdapter(List[DocumentMetadataSchema]).validate_python(res),
        )

    @classmethod
    def get_search_collections(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
        param: CollectionSearchSchema = Depends(),
    ) -> AsOutput[List[CollectionMetadataSchema]]:
        user: User = read.access.user(uuid_user)
        res: List[Collection] = read.search_user(user, param)
        return mwargs(
            AsOutput[List[CollectionMetadataSchema]],
            data=TypeAdapter(List[CollectionMetadataSchema]).validate_python(res),
        )


class UserView(BaseView):
    """Routes for user data and metadata.

    This will be put on ``/users``.
    """

    view_routes = dict(
        get_user=dict(
            url="/{uuid_user}",
            name="Read User",
        ),
        patch_user=dict(
            url="/{uuid_user}",
            name="Update User",
            responses=OpenApiResponseUnauthorized,
        ),
        delete_user=dict(
            url="/{uuid_user}",
            name="Delete User (and Associated Objects)",
            responses=OpenApiResponseUnauthorized,
        ),
        # post_user=dict(
        #     url="",
        #     name="Create a User",
        #     responses=OpenApiResponseUnauthorized,
        #     tags=[OpenApiTags.admin],
        # ),
    )
    view_router_args = dict(responses=OpenApiResponseUser, tags=[OpenApiTags.users])
    view_children = {"": UserSearchView}

    # TODO: Finish this once an acceptable prototype has been released.
    # @classmethod
    # def post_user(
    #     cls,
    #     token: DependsTokenOptional,
    #     create: DependsCreate,
    #     config: DependsConfig,
    #     create_data: UserCreateSchema,
    #     code: str | None = None,
    #     timestamp: int | None = None,
    # ) -> OutputWithEvents[UserSchema]:
    #     """Create a new user and return the user and creation event."""
    #
    #     if token is None:
    #         if code is None or timestamp is None:
    #             msg = "Code and timestamp are required (no token)."
    #             raise HTTPException(401, msg)
    #         cls.check_code(config, code, create_data.email, timestamp)
    #     elif token.tier != TokenPermissionTier.admin:
    #         msg = "Only admins may use this endpoint without a code."
    #         raise HTTPException(401, msg)
    #
    #     q = select(User.uuid).where(User.email == create_data.email)
    #     email_exists = create.session.scalar(q) is not None
    #     if email_exists:
    #         raise HTTPException(400, detail="Account with email already exists.")
    #
    #     create.create_data = create_data
    #     data: Data[ResolvedUser]
    #     data = mwargs(Data, token_user=None, data=ResolvedUser.empty())
    #     data_final = create.user(data)
    #     data_final.commit(create.session)
    #
    #     return mwargs(
    #         OutputWithEvents[UserSchema],
    #         data=UserSchema.model_validate(data_final.data.users[0]),
    #         events=[data_final.event],
    #     )
    #
    # @classmethod
    # def check_code(cls, config: Config, code: str, email: str, timestamp: int) -> None:
    #     now = int(datetime.timestamp(datetime.now()))
    #     if timestamp > now:
    #         raise HTTPException(422, detail="Code timestamp is from the future.")
    #     elif now - timestamp > config.auth0.registration_delay:
    #         raise HTTPException(422, detail="Code timestamp is too old.")
    #
    #     # NOTE: Code to expect should be the sum of the salt and the users
    #     #       email address.
    #     # NOTE: The Code is used because the only time that this should be used
    #     #       is when the auth0 registration flow is occuring.
    #     ts = bytes(timestamp)
    #     code_expect = hashlib.sha256(
    #         config.auth0.registration_code_salt + email.encode() + ts
    #     )
    #
    #     if code != code_expect.hexdigest():
    #         raise HTTPException(403, detail="Invalid code.")

    @classmethod
    def get_user(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
    ) -> AsOutput[UserSchema]:
        """Get `user` metadata.

        For instance, this could be used to make a profile page.
        """

        user = UserExtraSchema.model_validate(read.access.user(uuid_user))
        return mwargs(AsOutput[UserSchema], data=user)

    @classmethod
    def patch_user(
        cls,
        uuid_user: args.PathUUIDUser,
        update: DependsUpdate,
        updates: Annotated[UserUpdateSchema, Body()],
    ) -> OutputWithEvents[UserSchema]:
        """Update the `user` specified by **uuid_user**."""

        update.update_data = updates
        data: Data[ResolvedUser] = update.a_user(
            uuid_user,
            resolve_user_token=update.token_user,
        )
        return mwargs(
            OutputWithEvents[UserSchema],
            data=UserSchema.model_validate(data.data.users[0]),
            events=[data.event],
        )

    # @classmethod
    # def patch_restore_user(
    #     cls,
    #     uuid_user: args.PathUUIDUser,
    #     token: DependsTokenOptional,
    #     access: DependsAccess,
    # ):
    #     ...

    @classmethod
    def delete_user(
        cls,
        uuid_user: args.PathUUIDUser,
        delete: DependsDelete,
        restore: bool = False,
    ) -> None:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """

        data = delete.access.d_user(uuid_user)
        raise HTTPException(
            400,
            detail=(
                "User deactivation and deletion not yet supported."
                "(This is still a prototype)."
            ),
        )

        data = delete.a_user(uuid_user)
        data.commit(delete.session)
        # return mwargs(
        #     OutputWithEvents[UserSchema],
        #     events=[],
        #     data=UserSchema.model_validate(data.data.user[0]),
        # )
