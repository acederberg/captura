from typing import List, Set

from app import __version__
from app.depends import DependsSessionMaker, DependsToken
from app.models import (AssocUserDocument, Document, Event, KindEvent,
                        KindObject, Level, User)
from app.schemas import EventSchema, GrantCreateSchema, GrantSchema
from app.views import args
from app.views.base import BaseView
from fastapi import HTTPException
from sqlalchemy import literal_column, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true


class GrantView(BaseView):
    # NOTE: Updates should not be supported. It makes more sense to just delete
    #       the permissions and create new ones.
    view_routes = dict(
        delete_grants_document="/documents/{uuid_document}",
        # post_grants_document="/documents/{uuid_document}",
        get_grants_document="/documents/{uuid_document}",
        get_grants_user="/users/{uuid_user}",
        # delete_grants_user="/users/{uuid_user}",
        post_grants_user="/users/{uuid_user}",
    )

    @classmethod
    def verify_grantees(
        cls,
        session: Session,
        uuid_user: args.QueryUUIDUser,
    ) -> None:
        """Provided :param:`uuid_user`, look for uuids that do not exist.

        :param session: A session.
        :param uuid_user: Users to check for.
        :returns: Nothing.
        """

        if len(bad := uuid_user - uuid_user_existing):
            detail = dict(
                msg="Cannot grant to users that do not exist.",
                uuid_user=bad,
            )
            raise HTTPException(400, detail=detail)

    @classmethod
    def delete_grants_document(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUser,
    ) -> EventSchema:
        """Revoke access to the specified users on the specified document."""

        # NOTE: Permissions should be hard deleted unlike first class rows.
        #       Make sure that the revoker owns the specified document.
        uuid_revoker = token["uuid"]
        with makesession() as session:
            # logger.debug("Verifying document ownership.")
            document: Document = Document.if_exists(
                session, uuid_document
            ).check_not_deleted()
            (
                User.if_exists(session, uuid_revoker, 403)
                .check_not_deleted()
                .check_can_access_document(document, Level.own)
            )

            # NOTE: Look for users that do not exist or are deleted.
            cls.verify_grantees(session, uuid_user)

            # NOTE: Since owners cannot reject the ownership of other owners.
            # logger.debug("Verifying revokee permissions.")
            q_select_grants = document.q_select_grants(uuid_user)
            uuid_owners: Set[str] = set(
                session.execute(
                    select(literal_column("uuid_user"))
                    .select_from(q_select_grants)  # type: ignore
                    .where(literal_column("level") == Level.own)
                ).scalars()
            )
            if len(uuid_owners):
                detail = dict(
                    msg="Owner cannot reject grants of other owners.",
                    uuid_user_revoker=uuid_revoker,
                    uuid_user_revokees=uuid_owners,
                    uuid_documents=uuid_document,
                )
                raise HTTPException(403, detail=detail)

            # NOTE: Base event indicates the document, secondary event
            #       indicates the users for which permissions were revoked.
            #       Tertiary event indicates information about the association
            #       object. The shape of the tree is based off of the shape of
            #       the url on which this function can be called, where the
            #       document is first, the users are second, and the grants
            #       exist only as JSON.
            grants = list(session.execute(q_select_grants))
            event_common = dict(
                api_origin="DELETE /grants/documents/<uuid>",
                uuid_user=uuid_revoker,
                kind=KindEvent.grant,
            )
            event = Event(
                **event_common,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
                detail="Grants revoked.",
                children=[
                    Event(
                        **event_common,
                        kind_obj=KindObject.user,
                        uuid_obj=uuid_user,
                        detail=f"Grant `{grant.level.name}` revoked.",
                        children=[
                            Event(
                                **event_common,
                                kind_obj=KindObject.grant,
                                uuid_obj=grant.uuid,
                                detail=f"Grant `{grant.level.name}` revoked.",
                            )
                        ],
                    )
                    for grant in grants
                ],
            )
            session.add(event)
            session.execute(
                update(AssocUserDocument)
                .where(document.q_conds_grants(uuid_user))
                .values(deleted=True)
            )
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def get_grants_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocumentOptional = None,
    ) -> List[GrantSchema]:
        """Check that a user has access to the specified document.

        This function will likely be called in document CUD. But can be used
        to retrieve truthiness of an access level.
        """

        with makesession() as session:
            user = User.if_exists(session, token["uuid"])
            if user.uuid != uuid_user:
                detail = dict(msg="Users can only read their own grants.")
                raise HTTPException(403, detail=detail)

            assoc = session.execute(user.q_select_grants(uuid_document))
            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in assoc
            ]

    @classmethod
    def get_grants_document(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.QueryUUIDUserOptional = None,
    ) -> List[GrantSchema]:
        """List document grants.

        This could be useful somewhere in the UI. For instance, for owners
        granting permissions.
        """

        with makesession() as session:
            # Verify that user has access
            document = Document.if_exists(session, uuid_document).check_not_deleted(410)
            (
                User.if_exists(session, token["uuid"], 403)
                .check_not_deleted(410)
                .check_can_access_document(document, Level.own)
            )

            results = session.execute(document.q_select_grants(uuid_user))
            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in results
            ]

    @classmethod
    def post_grants_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        grants: List[GrantCreateSchema],
    ) -> EventSchema:
        """This endpoint can be used to share a document with another user.

        To revoke document access, use ``DELETE`` version of this endpoint. To
        undo grants from this endpoint, just send DELETE request to the same
        url. To this end, this endpoint is indempotent - posting existing
        grants will change nothing in the database, even if you change the
        level specified in the ``POST`` request.

        To see if a user had grants on a particluar document or not, use
        ``GET /grants/documents/<uuid>`` - To see all of a users grants use
        ``GET /grants/users/<uuid>``.


        :param uuid: Target uuid. The user to grant permissions to.
        :param level: Level to grant. One of "view", "modify", or
            "owner".
        :param uuid_document: The uuids of the documents to grant these
            permissions on.
        """

        with makesession() as session:
            # logger.debug("Verifying granter permissions.")
            document: Document = Document.if_exists(
                session, uuid_document
            ).check_not_deleted()

            granter: User = (
                User.if_exists(session, token["uuid"], 403)
                .check_not_deleted()
                .check_can_access_document(document, Level.own)
            )

            uuid_user: Set[str] = set(gg.uuid_user for gg in grants)
            cls.verify_grantees(session, uuid_user)

            # NOTE: Pick out grants that already exist. These grants will not
            #       be created and this will evident from the response.
            # logger.debug("Finding existing grants.")
            column_uuid_user = literal_column("uuid_user")
            q_uuid_grant_existing = select(column_uuid_user).select_from(
                document.q_select_grants(  # type: ignore
                    user_uuids=uuid_user,
                    exclude_deleted=False,
                ).where(AssocUserDocument.deleted == false())
            )
            q_uuid_grant_deleted = select(column_uuid_user).select_from(
                document.q_select_grants(  # type: ignore
                    user_uuids=uuid_user,
                    exclude_deleted=False,
                ).where(AssocUserDocument.deleted == true())
            )
            uuid_grant_existing, uuid_grant_deleted = (
                set(session.execute(q_uuid_grant_existing).scalars()),
                set(session.execute(q_uuid_grant_deleted).scalars()),
            )

            session.execute(
                update(AssocUserDocument)
                .where(AssocUserDocument.uuid.in_(uuid_grant_deleted))
                .values(deleted=False)
            )
            session.commit()
            uuid_grant_existing |= uuid_grant_deleted

            # logger.debug("Creating associations for grants.")
            assocs = {
                gg.uuid_user: AssocUserDocument(
                    id_user=User.if_exists(session, gg.uuid_user).id,
                    id_document=document.id,
                    level=gg.level,
                    deleted=False,
                )
                for gg in grants
                if gg.uuid_user not in uuid_grant_existing
            }
            session.add_all(assocs.values())
            session.commit()

            # NOTE: Events returned by this endpoint should look like those
            #       returned from the corresponding DELETE endpoint.
            logger.debug("Creating events for grant.")
            common = dict(
                kind=KindEvent.grant,
                uuid_user=granter.uuid,
                api_origin="POST /grants/documents/<uuid>",
                api_version=__version__,
            )
            event = Event(
                **common,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
                detail="Grants issued.",
                children=[
                    Event(
                        **common,
                        uuid_obj=uuid_user,
                        kind_obj=KindObject.user,
                        detail=f"Grant `{assoc.level.name}` issued.",
                        children=[
                            Event(
                                **common,
                                uuid_obj=assoc.uuid,
                                kind_obj=KindObject.grant,
                                detail=f"Grant `{assoc.level.name}` issued.",
                            )
                        ],
                    )
                    for uuid_user, assoc in assocs.items()
                ],
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)
