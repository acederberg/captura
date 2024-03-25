from typing import Annotated, List, Set, Tuple

from app import __version__, fields
from app.controllers.base import (Data, ResolvedDocument,
                                  ResolvedGrantDocument, ResolvedGrantUser,
                                  ResolvedUser)
from app.depends import (DependsAccess, DependsCreate, DependsDelete,
                         DependsSessionMaker, DependsToken, DependsUpdate)
from app.err import (AnyErrDetailAccessDocumentGrant,
                     ErrAccessDocumentCannotRejectOwner,
                     ErrAccessDocumentGrantBase,
                     ErrAccessDocumentGrantInsufficient,
                     ErrAccessDocumentPending, ErrAccessUser, ErrDetail)
from app.models import (AssocUserDocument, Document, Event, Grant, KindEvent,
                        KindObject, Level, LevelStr, User)
from app.schemas import (AsOutput, EventSchema, GrantCreateSchema, GrantSchema,
                         OutputWithEvents, mwargs)
from app.views import args
from app.views.base import (BaseView, OpenApiResponseCommon,
                            OpenApiResponseDocumentForbidden,
                            OpenApiResponseUnauthorized, OpenApiTags)
from fastapi import HTTPException
from pydantic import TypeAdapter
from sqlalchemy import literal_column, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true


class DocumentGrantView(BaseView):
    # NOTE: Updates should not be supported. It makes more sense to just delete
    #       the permissions and create new ones.
    view_routes = dict(
        delete_grants_document=dict(
            url="/{uuid_document}",
            name="Revoke Document Access for Users",
            # A true one off.
            responses={
                403: dict(
                    description="Cannot revoke grants of other owners.",
                    model=ErrDetail[ErrAccessDocumentCannotRejectOwner],
                )
            },
        ),
        post_grants_document=dict(
            url="/{uuid_document}",
            name="Invite Users to Access Document",
        ),
        get_grants_document=dict(
            url="/{uuid_document}",
            name="Read User Grants/Grant Requests for Document",
        ),
        patch_grants_document=dict(
            url="/{uuid_document}",
            name="Accept/Reject User Grant Requests for Document",
        ),
    )

    view_router_args = dict(
        tags=[OpenApiTags.grants],
        responses={
            **OpenApiResponseCommon,
            **OpenApiResponseUnauthorized,
            **OpenApiResponseDocumentForbidden,
        },
    )

    @classmethod
    def delete_grants_document(
        cls,
        delete: DependsDelete,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Revoke access to **document** for the **users** specified by
        `uuid_user`.
        """

        data: Data[ResolvedGrantDocument] = delete.a_grant_document(
            uuid_document,
            uuid_user,
        )
        data.commit(delete.session, True)
        return mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(
                data.data.grants.values()
            ),
            events=[data.event],
        )

    @classmethod
    def get_grants_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUserOptional = None,
        pending: bool = False,
        pending_from: args.QueryPendingFromOptional = None,
    ) -> AsOutput[List[GrantSchema]]:
        """List the active grants for a **document**. If `uuid_user` is
        specified, then filter results by these users; otherwise, return all
        of the grants for **document**.

        To view grant requests set `pending` to be `True`. It is important to
        note that access to the users is not checked, because, for instance,
        a private user might be assigned to the document.
        """

        data: Data[ResolvedGrantDocument] = access.d_grant_document(
            uuid_document,
            uuid_user,
            level=Level.view,
            pending=pending,
        )
        grants = data.data.grants.values()
        if pending_from:
            pending_from_ = fields.PendingFrom[pending_from.name]
            grants = list(v for v in grants if v.pending_from == pending_from_)

        out = mwargs(
            AsOutput,
            data=TypeAdapter(List[GrantSchema]).validate_python(grants),
        )
        return out

    @classmethod
    def post_grants_document(
        cls,
        create: DependsCreate,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
        level: args.QueryLevel = LevelStr.view,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Invite users to access a document by creating pending grants. Users
        will have to accept new grants.

        To request access to a document, use `POST /grants/users/<uuid>`.


        ### When `force=true`

        When grants exist, they are replaced and those invited must re-accept
        their grant to have any access.

        Eventually this will not be necessary. So for instance a user with
        `modify` permissions can be demoted to `view` permissions without
        having to accept another grant.


        ### When `force=false`

        When grants exist, they are not replaced or modified in any way and
        the non-existing grants are created. This will result in this endpoint
        being indempotent in this case and is why it is possibly to get single
        layered events out of this endpoint.
        """
        # NOTE: Level filters grants.
        fr_level = Level.resolve(level) if level is not None else None
        data: Data[ResolvedGrantDocument] = create.access.d_grant_document(
            uuid_document,
            uuid_user,
            level=fr_level, 
        )
        create.create_data = GrantCreateSchema(level=fr_level)
        create.grant_document(data)
        data.commit(create.session, True)

        return mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(
                data.data.grants.values()
            ),
            events=[EventSchema.model_validate(data.event)],
        )

    @classmethod
    def patch_grants_document(
        cls,
        update: DependsUpdate,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Accept any grant requests *(likely made via
        `PATCH /grants/users/{uuid_user}`)*. To reject invitations use the 
        corresponding ``Delete`` endpoint.

        Updating grants in place is not permitted. To replace a grant use
        `POST /grants/users/{uuid_user}` with `force=true`.
        """

        data: Data[ResolvedGrantDocument] = update.access.d_grant_document(
            uuid_document,
            uuid_user,
            level=Level.own,
        )
        update.grant_document(data)
        data.commit(update.session)
        assert data.event is not None

        out = mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(data.data.grants.values()),
            events=[EventSchema.model_validate(data.event)]
        )
        return out

class UserGrantView(BaseView):
    view_routes = dict(
        get_grants_user=dict(
            url="/{uuid_user}",
            name="Read User Access/Invitations to Documents",
        ),
        delete_grants_user=dict(
            url="/{uuid_user}",
            name="Revoke User Access to Documents",
        ),
        post_grants_user=dict(
            url="/{uuid_user}",
            name="Request User Access to Documents",
            response_description="New grants and their events.",
        ),
        patch_grants_user=dict(
            url="/{uuid_user}", name="Accept/Reject User Invitations to Documents"
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.grants],
        responses={
            **OpenApiResponseCommon,
            **OpenApiResponseUnauthorized,
            403: dict(
                model=ErrDetail[ErrAccessUser],
                description=(
                    "User is not the user specified by `uuid_user` or an " "admin."
                ),
            ),
        },
    )

    @classmethod
    def delete_grants_user(
        cls,
        delete: DependsDelete,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocument,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Revoke grants for a **user** for the provided **documents**. The
        intended use case is for users/admins to revoke their own grants.
        """

        data: Data[ResolvedGrantUser] = delete.a_grant_user(
            uuid_user,
            uuid_document,
            exclude_deleted=not delete.force,
        )
        data.commit(delete.session, True)
        return mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(
                data.data.grants.values()
            ),
            events=[data.event],
        )

    @classmethod
    def get_grants_user(
        cls,
        access: DependsAccess,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocumentOptional = None,
        level: args.QueryLevel | None = None,
        pending: bool = False,
        pending_from: args.QueryPendingFromOptional = None,
    ) -> AsOutput[List[GrantSchema]]:
        """Get grants for a **user**. The indented use case is for users/admins
        to view the grants for any user. If **uuid_document** is not specified
        then all grants for the user are returned.

        To view grant requests set `pending` to be `True`.
        """

        data: Data[ResolvedGrantUser] = access.d_grant_user(
            uuid_user,
            uuid_document,
            pending=pending,
            level=level,
        )
        if pending_from:
            grant = {
                k: v
                for k, v in data.data.grants.items()
                if v.pending_from == pending_from
            }

        grant = data.data.grants.values()
        return mwargs(
            AsOutput[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(grant),
        )

    @classmethod
    def patch_grants_user(
        cls,
        update: DependsUpdate,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocument,
    ) -> AsOutput[List[GrantSchema]]:
        """Approve pending grants for user. The intended use case is for users
        to accept their own grants (this can also be done by admins).

        To invite users to a document you own, use
        `POST /grants/documents/{uuid}`.

        Note that grants cannot be updated in place. To replace/update a grant
        use `POST /grants/users/{uuid}` endpoint with `force=true`."""

        data: Data[ResolvedGrantDocument] = update.access.d_grant_user(
            uuid_user,
            uuid_document,
            # level=Level.view,
            pending=True,
            # exclude_pending=False,
            # pending_from=PendingFrom.granter
        )
        update.grant_document(data)
        data.commit(update.session)
        assert data.event is not None

        out = mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(data.data.grants.values()),
            events=[EventSchema.model_validate(data.event)]
        )
        return out

    @classmethod
    def post_grants_user(
        cls,
        create: DependsCreate,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocument,
        level: args.QueryLevel,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Request **user** access to *public* **documents** specified by
        **uuid_document**. These grants will await approval from a document
        owner or admin view `PATCH /grants/documents/{uuid_document}`.

        This does not have `force` as users will likely never have a use case
        to drop their own **Level**.
        """

        # NOTE: Use does not have access to the requested documents typically.
        #       The only requirement to ask for access is to know the document
        #       uuid, which would be difficult to geuss in the case of.
        # NOTE: `token_user_grants` is usually the same as grants. But in this
        #       case they are not used. `grants` will be updated inside of
        #       `create.grant_user`.

        # user: User = create.access._user(uuid_user)
        # data: Data[ResolvedGrantUser] = mwargs(
        #     Data[ResolvedGrantUser],
        #     data=mwargs(
        #         ResolvedGrantUser,
        #         user=user,
        #         documents=Document.resolve(create.session, uuid_document),
        #         grants=dict(),
        #         token_user_grants=dict(),
        #     ),
        # )
        data: Data[ResolvedGrantUser] = create.access.d_grant_user(
            uuid_user,
            uuid_document,
            # exclude_pending=False,
            # pending_from=PendingFrom.granter
        )
        create.create_data = GrantCreateSchema(level=level)
        create.grant_user(data)

        # Get rid of grants that already exist.
        data.commit(create.session, True)
        grants = data.data.grants
        return mwargs(
            OutputWithEvents[List[GrantSchema]],
            data=TypeAdapter(List[GrantSchema]).validate_python(grants.values()),
            events=[EventSchema.model_validate(data.event)],
        )
