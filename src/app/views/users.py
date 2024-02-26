import secrets
from http import HTTPMethod
from typing import Annotated, Any, Dict, List, Literal, Set, Tuple
from uuid import uuid4

from app import __version__, util
from app.controllers.access import Access
from app.depends import (DependsAccess, DependsDelete, DependsRead,
                         DependsSessionMaker, DependsToken)
from app.models import (Collection, Document, Edit, Event, KindEvent,
                        KindObject, User)
from app.schemas import (CollectionMetadataSchema, CollectionSearchSchema,
                         DocumentMetadataSchema, DocumentSearchSchema,
                         EditMetadataSchema, EditSearchSchema, EventSchema,
                         UserCreateSchema, UserExtraSchema, UserSchema,
                         UserSearchSchema, UserUpdateSchema, WithEvents)
from app.views import args
from app.views.base import BaseView
from fastapi import Body, Depends, HTTPException, Query
from pydantic import TypeAdapter
from sqlalchemy import select


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
        post_user_demo="",
        get_user_demos="",
        patch_user_demo="/{invitation_uuid}",
    )

    @classmethod
    def get_user_demos(
        cls,
        access: DependsAccess,
        invitation_email: Annotated[Set[str] | None, Query()] = None,
        invitation_code: Annotated[Set[str] | None, Query()] = None,
        invitation_uuid: Annotated[Set[str] | None, Query()] = None,
    ) -> List[WithEvents[UserExtraSchema]]:
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
        util.sql(session, q_user)
        users = tuple(session.execute(q_user).scalars())

        adapter = TypeAdapter(List[EventSchema]) 
        return list(
            WithEvents[UserExtraSchema].model_construct(
                data=UserExtraSchema.model_validate(user),
                events=adapter.validate_python(
                    session.execute(user.q_events()).scalars()
                ) 
            )
            for user in users
        )


    @classmethod
    def post_user_demo(
        cls,
        access: DependsAccess,
        user_in: UserCreateSchema,
        invitation_email: Annotated[str, Query()], 
        force: Annotated[bool, Query()] = False
    ) -> WithEvents[UserExtraSchema]:
        """Create a user.

        When an admin posts to this function, the admin should specify initial
        details requested for approval.
        """
        is_admin = access.token.admin
        user_uuid = secrets.token_urlsafe(8)
        q_name = select(User).where(User.name == user_in.name)

        session = access.session
        events: List[Event] = list()
        if (user_existing := session.execute(q_name).scalar()) is not None:
            if force:
                if not is_admin:
                    raise HTTPException(403, detail=dict(
                        msg="The force is only for masters.",
                        uuid=invitation_email,
                    ))
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
                raise HTTPException(422, detail=dict(
                    msg="User with username already exists.",
                    name=user_in.name,
                ))

        detail = "Demo user "
        detail += "created by admin." if is_admin else "requested"
        events.append( event := Event(
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

        return WithEvents[UserExtraSchema].model_construct(
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
    ) -> WithEvents[UserExtraSchema]:
        """If an admin, approves the user request made with `POST /users/demo`.
        If not an admin, this can be used to active an account with the 
        :param:`invitation_uuid`.
        """

        # NOTE: There is no access to check in this case. Just the invitation.
        q_user = select(User).where(
            User._prototype_activation_invitation_code==invitation_code,
            User._prototype_activation_invitation_email==invitation_email,
            User.uuid==invitation_uuid,
        )

        event_kwargs = dict(
            api_origin="PATCH `/users/demo/<uuid_user>`.",
            api_version=__version__,
            uuid_user=access.token_user.uuid,
            uuid_obj=invitation_uuid,
            kind_obj=KindObject.user,
            kind=KindEvent.update
        )

        status: int | None = None
        msg: str |  None = None
        session = access.session
        match (user := session.execute(q_user).scalar()):
            case None:
                msg ="Incorrect combination of `invitation_code` and "
                msg += "`invitation_email`."
                raise HTTPException(403, detail=msg) 
            # NOTE: 422 because the request 
            case User( deleted=False, pending_approval=False, uuid=uuid):
                status = 422
                msg ="User already activated."
            # NOTE: 500 because this should never happen.
            case User( deleted=False, pending_approval=True, uuid=uuid):
                status = 500
                msg = "User is already out of deleted state while pending "
                msg += "approval."
            # Update user and return response.
            case User(deleted=True, pending_approval=True, uuid=uuid):
                if access.token.admin:
                    user._prototype_activation_pending_approval = False
                    session.add(user)
                    session.add(
                        event := Event(
                            detail="Admin approved invitation.",
                            **event_kwargs,
                        )
                    )
                    session.commit()
                    session.refresh(user)
                else:
                    status = 403
                    msg = "Only admins can approve a demo user.",
            case User( deleted=True, pending_approval=False, uuid=uuid):
                # User answered correctly. This should be possible without a 
                # token 
                user.deleted = False
                session.add(user)
                session.add(event := Event(
                    detail="Account activated.",
                    **event_kwargs,
                ))
                session.commit()
                session.refresh(user)

            case _:
                raise HTTPException(500)



        if msg is not None:
            if status is None:
                raise HTTPException(500)
            raise HTTPException(status, detail=dict(msg=msg, uuid_user=uuid))

        return WithEvents[UserExtraSchema].model_construct(
            data=UserExtraSchema.model_validate(user),
            events=TypeAdapter(List[EventSchema]).validate_python(
                session.execute(user.q_events()).scalars()
            )
        )


class UserSearchView(BaseView):
    """Separate from :class:`UserView` so that it is clear that this is the
    sole batch of endpoints through which ``search`` style results are
    available. All other controllers should only support get by ``uuid``(s).
    """

    view_routes = dict(
        get_search_users="/{uuid_user}/users",
        #                  ^^^^^^^^^^^  Search results ALWAYS scoped for users 
        #                               by uuid (since admins might need to 
        #                               simulate search results of other 
        #                               users).
        get_search_documents="/{uuid_user}/documents",
        get_search_edits="/{uuid_user}/edits",
        get_search_collections="/{uuid_user}/collections",
    )

    # ----------------------------------------------------------------------- #

    # NOTE: This includes the path parameter so that admins may simulate
    #       exactly the search results of another user.
    @classmethod
    def get_search_users(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
        param: Annotated[UserSearchSchema, Depends()],
    ) -> List[UserSchema]:
        """Get user collaborators or just list some users."""

        user: User = read.access.user(uuid_user)
        res: Tuple[User, ...] = read.search_user(user, param)
        return TypeAdapter(List[UserSchema]).validate_python(res)

    # TODO: Test that users cannot access private docs/colls of others here. 
    @classmethod
    def get_search_documents(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
        param: DocumentSearchSchema = Depends(),
    ) -> List[DocumentMetadataSchema]:

        user: User = read.access.user(uuid_user)
        res: Tuple[Document, ...] = read.search_user(user, param)
        return TypeAdapter(List[DocumentMetadataSchema]).validate_python(res)

    @classmethod
    def get_search_collections(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
        param: CollectionSearchSchema = Depends(),
    ) -> List[CollectionMetadataSchema]:

        user: User = read.access.user(uuid_user)
        res: Tuple[Collection, ...] = read.search_user(user, param)
        return TypeAdapter(List[CollectionMetadataSchema]).validate_python(res)

    @classmethod
    def get_search_edits(
        cls,
        uuid_user: args.PathUUIDUser,
        read: DependsRead,
        param: EditSearchSchema = Depends(),
    ) -> List[EditMetadataSchema]:
        user: User = read.access.user(uuid_user)
        res: Tuple[Edit, ...] = read.search_user(user, param)
        return TypeAdapter(List[EditMetadataSchema]).validate_python(res)


class UserView(BaseView):
    """Routes for user data and metadata.

    This will be put on ``/users``.
    """

    view_routes = dict(
        get_user="/{uuid_user}",
        patch_user="/{uuid_user}",
        delete_user="/{uuid_user}",
    )
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
    ) -> UserSchema:
        """Get user metadata.

        For instance, this should be used to make a profile page.
        """

        user: User = read.access.user(uuid_user)
        return UserSchema.model_validate(user)

    @classmethod
    def patch_user(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        updates: Annotated[UserUpdateSchema, Body()]
    ) -> EventSchema:
        """Update a user.

        Only the user themself should be able to update this.
        """

        with sessionmaker() as session:
            user = Access(session, token).user(uuid)

            # NOTE: Don't forget to include the metadata.
            updates_dict = updates.model_dump()
            event_common = dict(
                uuid_user=token["uuid"],  # use from token incase bad access.
                uuid_obj=uuid,
                kind=KindEvent.update,
                kind_obj=KindObject.user,
                api_origin="PATCH /users/<uuid>",
            )
            event = Event(**event_common, detail="Updated user.")
            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(user, key, value)
                event.children.append(
                    Event(**event_common, detail=f"Updated user {key}.")
                )
            session.add(event)
            session.add(user)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def delete_user(
        cls,
        uuid_user: args.PathUUIDUser,
        delete: DependsDelete,
        restore: bool = False,
    ) -> EventSchema:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """

        if restore:
            raise HTTPException(400, detail="Not yet implemented.")

        data = delete.a_user(uuid_user)
        return EventSchema.model_validate(data.event)


        
