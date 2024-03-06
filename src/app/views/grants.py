from typing import List, Set

from app import __version__
from app.depends import (DependsAccess, DependsCreate, DependsDelete,
                         DependsSessionMaker, DependsToken, DependsUpdate)
from app.models import (AssocUserDocument, Document, Event, KindEvent,
                        KindObject, Level, User)
from app.schemas import (AsOutput, ErrAccessDocument, ErrAccessUser, ErrDetail,
                         EventSchema, GrantCreateSchema, GrantSchema,
                         OutputWithEvents)
from app.views import args
from app.views.base import BaseView, OpenApiResponseCommon, OpenApiTags
from fastapi import HTTPException
from sqlalchemy import literal_column, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true


class DocumentGrantView(BaseView):
    # NOTE: Updates should not be supported. It makes more sense to just delete
    #       the permissions and create new ones.
    view_routes = dict(
        delete_grants_document=dict(
            url="/{uuid_document}",
            name="Revoke Document Access for Users"
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
            403: dict(
                model=ErrDetail[ErrAccessDocument],
                description=(
                    "User is not an owner of the document specified by "
                    "`uuid_document` or an admin."
                )
            )
        },
    )

    @classmethod
    def delete_grants_document(
        cls,
        delete: DependsDelete,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
    ) -> OutputWithEvents[GrantSchema]:
        """Revoke access to **document** for the **users** specified by 
        `uuid_user`. 
        """
        ...

    @classmethod
    def get_grants_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUserOptional = None,
        pending: bool = False,
    ) -> AsOutput[List[GrantSchema]]:
        """List the active grants for a **document**. If `uuid_user` is 
        specified, then filter results by these users; otherwise, return all
        of the grants for **document**.

        To view grant requests set `pending` to be `True`.
        """
        ...

    @classmethod
    def post_grants_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUserOptional,
        grants: List[GrantCreateSchema],
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Invite users to access a document by creating pending grants. Users
        will have to accept new grants.

        To request access to a document, use `POST /grants/users/<uuid>`.

        When existing, accepting grants are replaced (by specifying force),
        without awaiting user acceptance of their new grant `Level`.
        """
        ...

    @classmethod
    def patch_grants_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
        accept: bool = False,
    ) -> OutputWithEvents[List[GrantSchema]]:
        """Accept any grant requests *(likely made via
        `PATCH /grants/users/{uuid_user}`)*.

        Updating grants in place is not permitted. To replace a grant use
        `POST /grants/users/{uuid_user}` with `force=true`.
        """
        ...
        

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
        ),
        patch_grants_user=dict(
            url="/{uuid_user}",
            name="Accept/Reject User Invitations to Documents"
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.grants],
        responses={
            **OpenApiResponseCommon,
            403: dict(
                model=ErrDetail[ErrAccessUser],
                description=(
                    "User is not the user specified by `uuid_user` or an "
                    "admin."
                )
            )
        }
    )

    @classmethod
    def delete_grants_user(
        cls,
        delete: DependsDelete,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocument,
    ) -> OutputWithEvents[GrantSchema]:
        """Revoke grants for a **user** for the provided **documents**. The 
        intended use case is for users/admins to revoke their own grants.
        """

        ...

    @classmethod
    def get_grants_user(
        cls,
        access: DependsAccess,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocumentOptional = None,
        pending: bool = False,
    ) -> AsOutput[List[GrantSchema]]:
        """Get grants for a **user**. The indented use case is for users/admins 
        to view the grants for any user. If **uuid_document** is not specified
        then all grants for the user are returned.

        To view grant requests set `pending` to be `True`.
        """
        ...

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
        ...

    @classmethod
    def post_grants_user(
        cls,
        create: DependsCreate,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocument,
        create_data: List[GrantCreateSchema],
    ) -> AsOutput[List[GrantSchema]]:
        """Request **user** access to *public* **documents** specified by 
        **uuid_document**. These grants will await approval from a document
        owner or admin view `PATCH /grants/documents/{uuid_document}`.

        This does not have `force` as users will likely never have a use case
        to drop their own **Level**.
        """
        ...
