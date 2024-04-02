# =========================================================================== #
import secrets
from typing import Annotated, List, Set, Tuple
from uuid import uuid4

from fastapi import Body, Depends, HTTPException, Query
from pydantic import TypeAdapter
from sqlalchemy import select

# --------------------------------------------------------------------------- #
from app import __version__, util
from app.controllers.base import Data, ResolvedUser
from app.depends import DependsAccess, DependsDelete, DependsRead, DependsUpdate
from app.err import ErrAccessUser, ErrDetail
from app.models import Collection, Document, Edit, Event, KindEvent, KindObject, User
from app.schemas import (
    AsOutput,
    CollectionMetadataSchema,
    CollectionSearchSchema,
    DocumentMetadataSchema,
    DocumentSearchSchema,
    EditMetadataSchema,
    EditSearchSchema,
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


class DemoUserView(BaseView):
    """Routes for user data and metadata.

    Demo User Creation/Activation Flow
    ---------------------------------------------------------------------------

    The following:

      1. A human requests an account via "POST /user/demo". The accounts
        user is created with pending approval (The `user` will have
        `_prototype_activation_pending_approval=True` and
        `deleted=True`) waiting for an admin to accept their invitation
        request with `PATCH /users/demo`.
      2. The accounts `user` is approved by and admin with `PATCH
        /users/demo` as stated above.
      3. The user moves their account out `deleted` state by doing a
        `PATCH /users/demo`.
    """

    view_routes = dict(
        post_user_demo=dict(
            url="",
            name="Request a Demo User",
        ),
        get_user_demos=dict(
            url="",
            name="Read Demo Requests",
        ),
        patch_user_demo=dict(
            url="/{invitation_uuid}",
            name="Admin Approve Request/Auth0 Verify",
        ),
    )

    view_router_args = dict(
        tags=[OpenApiTags.users],
        responses=OpenApiResponseUser,
    )

    @classmethod
    def get_user_demos(
        cls,
        access: DependsAccess,
        invitation_email: Annotated[Set[str] | None, Query()] = None,
        invitation_code: Annotated[Set[str] | None, Query()] = None,
        invitation_uuid: Annotated[Set[str] | None, Query()] = None,
    ) -> List[OutputWithEvents[UserExtraSchema]]:
        """Get requests for demo accounts.

        Optionally filter by **invitation_email**, **invitation_code**, or
        **invitation_uuid**.
        """

        if not access.token.admin:
            raise HTTPException(
                403,
                detail="Only admins can view demo users.",
            )

        session = access.session
        q_user = User._q_prototype_activation_pending_approval(
            invitation_uuid=invitation_uuid,
            invitation_code=invitation_code,
            invitation_email=invitation_email,
        )
        # util.sql(session, q_user)
        users = tuple(session.execute(q_user).scalars())

        adapter = TypeAdapter(List[EventSchema])
        return list(
            mwargs(
                OutputWithEvents[UserExtraSchema],
                data=UserExtraSchema.model_validate(user),
                events=adapter.validate_python(
                    session.execute(user.q_events()).scalars()
                ),
            )
            for user in users
        )

    @classmethod
    def post_user_demo(
        cls,
        access: DependsAccess,
        user_in: UserCreateSchema,
        invitation_email: Annotated[str, Query()],
        force: Annotated[bool, Query()] = False,
    ) -> OutputWithEvents[UserExtraSchema]:
        """Create a user.

        If the user has no token or has a valid token but is not an admin, the
        `user` created will await approval from an admin. If the token exists
        and is an for an `admin`, then the `user` created will only await
        activation via `PATCH /users/extensions/demo/{invitation_code}`
        """
        is_admin = access.token.admin
        user_uuid = secrets.token_urlsafe(8)
        q_name = select(User).where(User.name == user_in.name)

        session = access.session
        events: List[Event] = list()
        if (user_existing := session.execute(q_name).scalar()) is not None:
            if force:
                if not is_admin:
                    raise HTTPException(
                        403,
                        detail=dict(
                            msg="The force is only for masters.",
                            uuid=invitation_email,
                        ),
                    )
                events.append(
                    event_user_existing := Event(
                        api_version=__version__,
                        api_origin="POST `/users/demo`",
                        detail="Invitation force deleted.",
                        uuid_obj=user_existing.uuid,
                        kind_obj=KindObject.user,
                        uuid_user=access.token_user.uuid,
                        kind=KindEvent.delete,
                    )
                )
                session.delete(user_existing)
                session.add(event_user_existing)
                session.commit()

            else:
                raise HTTPException(
                    422,
                    detail=dict(
                        msg="User with username already exists.",
                        name=user_in.name,
                    ),
                )

        detail = "Demo user "
        detail += "created by admin." if is_admin else "requested"
        events.append(
            event := Event(
                api_version=__version__,
                api_origin="POST `/users/demo`",
                detail=detail,
                uuid_obj=user_uuid,
                kind_obj=KindObject.user,
                uuid_user=access.token_user.uuid,
                kind=KindEvent.create,
            )
        )
        invitation_code = str(uuid4())
        user = User(
            _prototype_activation_invitation_email=invitation_email,
            _prototype_activation_invitation_code=invitation_code,
            _prototype_activation_pending_approval=is_admin,
            uuid=user_uuid,
            **user_in.model_dump(exclude={"kind"}),
            deleted=True,
        )

        session.add(event)
        session.add(user)
        session.commit()
        session.refresh(event)
        session.refresh(user)

        return mwargs(
            OutputWithEvents[UserExtraSchema],
            data=UserExtraSchema.model_validate(user),
            events=[event],
        )

    @classmethod
    def patch_user_demo(
        cls,
        access: DependsAccess,
        invitation_uuid: args.PathUUIDUser,
        invitation_code: Annotated[str, Query()],
        invitation_email: Annotated[str, Query()],
    ) -> OutputWithEvents[UserExtraSchema]:
        """If user has a valid token and is an admin, approves the user request
        made with `POST /users/demo` matching **invitation_uuid**,
        **invitation_code**, and **invitation_email**.

        If not an admin, this should be used by auth0 to activate an account
        by verifying the afforementioned parameters.
        """

        # NOTE: There is no access to check in this case. Just the invitation.
        q_user = select(User).where(
            User._prototype_activation_invitation_code == invitation_code,
            User._prototype_activation_invitation_email == invitation_email,
            User.uuid == invitation_uuid,
        )

        event_kwargs = dict(
            api_origin="PATCH `/users/demo/<uuid_user>`.",
            api_version=__version__,
            uuid_user=access.token_user.uuid,
            uuid_obj=invitation_uuid,
            kind_obj=KindObject.user,
            kind=KindEvent.update,
            detail="Demo user activation.",
        )

        status: int | None = None
        msg: str | None = None
        session = access.session
        match (user := session.execute(q_user).scalar()):
            case None:
                msg = "Incorrect combination of `invitation_code` and "
                msg += "`invitation_email`."
                raise HTTPException(403, detail=msg)
            # NOTE: 422 because the request
            case User(deleted=False, pending_approval=False, uuid=uuid):
                status = 422
                msg = "User already activated."
            # NOTE: 500 because this should never happen.
            case User(deleted=False, pending_approval=True, uuid=uuid):
                status = 500
                msg = "User is already out of deleted state while pending "
                msg += "approval."
            # Update user and return response.
            case User(deleted=True, pending_approval=True, uuid=uuid):
                if access.token.admin:
                    user._prototype_activation_pending_approval = False
                    session.add(user)
                    session.add(
                        Event(
                            message="Admin approved invitation.",
                            **event_kwargs,
                        )
                    )
                    session.commit()
                    session.refresh(user)
                else:
                    status = 403
                    msg = "Only admins can approve a demo user."
            case User(deleted=True, pending_approval=False, uuid=uuid):
                # NOTE: User answered correctly. This should be possible
                #       without a token.
                user.deleted = False
                session.add(user)
                session.add(
                    Event(
                        message="Account activated.",
                        **event_kwargs,
                    )
                )
                session.commit()
                session.refresh(user)
            case _:
                raise HTTPException(500)

        if msg is not None:
            if status is None:
                raise HTTPException(500)
            raise HTTPException(status, detail=dict(msg=msg, uuid_user=uuid))

        return mwargs(
            OutputWithEvents[UserExtraSchema],
            data=UserExtraSchema.model_validate(user),
            events=TypeAdapter(List[EventSchema]).validate_python(
                session.execute(user.q_events()).scalars()
            ),
        )


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
        # get_search_edits=dict(
        #     url="/{uuid_user}/edits",
        #     name="Search User Edits",
        # ),
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

        res: Tuple[User, ...] = read.search_user(user, param)
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
        res: Tuple[Document, ...] = read.search_user(user, param)
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
        res: Tuple[Collection, ...] = read.search_user(user, param)
        return mwargs(
            AsOutput[List[CollectionMetadataSchema]],
            data=TypeAdapter(List[CollectionMetadataSchema]).validate_python(res),
        )

    # @classmethod
    # def get_search_edits(
    #     cls,
    #     uuid_user: args.PathUUIDUser,
    #     read: DependsRead,
    #     param: EditSearchSchema = Depends(),
    # ) -> AsOutput[List[EditMetadataSchema]]:
    #     user: User = read.access.user(uuid_user)
    #     res: Tuple[Edit, ...] = read.search_user(user, param)
    #     return mwargs(
    #         AsOutput[List[EditMetadataSchema]],
    #         data=TypeAdapter(List[EditMetadataSchema]).validate_python(res),
    #     )


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
    )
    view_router_args = dict(responses=OpenApiResponseUser, tags=[OpenApiTags.users])
    view_children = {
        "/extensions/demos": DemoUserView,
        "": UserSearchView,
    }

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    # At this point reject bad tokens. A private user should be the
    # only user able to read their own account.
    @classmethod
    def get_user(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
    ) -> AsOutput[UserExtraSchema]:
        """Get `user` metadata.

        For instance, this could be used to make a profile page.
        """

        user = UserExtraSchema.model_validate(read.access.user(uuid_user))
        return mwargs(AsOutput[UserExtraSchema], data=user)

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

    @classmethod
    def delete_user(
        cls,
        uuid_user: args.PathUUIDUser,
        delete: DependsDelete,
        restore: bool = False,
    ) -> OutputWithEvents[UserSchema]:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """

        if restore:
            raise HTTPException(400, detail="Not yet implemented.")

        data = delete.a_user(uuid_user)
        return mwargs(
            OutputWithEvents[UserSchema],
            events=[EventSchema.model_validate(data.event)],
            data=UserSchema.model_validate(data.data.user[0]),
        )
