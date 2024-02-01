from typing import Any, Dict, List, Set, Tuple

from app import __version__, util
from app.depends import DependsSessionMaker, DependsToken
from app.models import (
    AssocCollectionDocument,
    Collection,
    Document,
    Event,
    KindEvent,
    KindObject,
    Level,
    User,
)
from app.schemas import AssignmentSchema, EventSchema
from app.views import args
from app.views.access import Access
from app.views.base import BaseView
from fastapi import HTTPException
from sqlalchemy import delete, literal_column, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true


# NOTE: Should mirron :class:`GrantView`. Updates not supported, scoped by
#       collection.
class AssignmentView(BaseView):
    view_routes = dict(
        delete_assignment_collection="/collections/{uuid_collection}",
        post_assignment_collection="/collections/{uuid_collection}",
        get_assignment_collection="/collections/{uuid_collection}",
        delete_assignment_document="/documents/{uuid_document}",
        post_assignment_document="/documents/{uuid_document}",
        get_assignment_document="/documents/{uuid_document}",
    )

    @classmethod
    def split_assignments(
        cls,
        session: Session,
        item,
        uuid_values: Set[str],
        uuid_column,
    ) -> Tuple[Set[str], Set[str]]:
        q = item.q_select_assignment(uuid_values, exclude_deleted=False)
        exps = tuple(
            select(uuid_column).select_from(
                q.where(AssocCollectionDocument.deleted == bool_()).subquery()
            )
            for bool_ in (true, false)
        )

        out = tuple(set(session.execute(exp).scalars()) for exp in exps)
        return out  # type: ignore

    @classmethod
    def delete_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollection,
        force: args.QueryForce = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, (document,), _ = Access(session, token).assignment(
                uuid_document={uuid_document},
                uuid_collection=uuid_collection,
                level=Level.own,
                exclude_deleted=False,
            )

            # NOTE: Ignore entries that are already deletd.
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, document, uuid_collection, literal_column("uuid")
            )

            if force:
                detail = "Assignment force deleted."
                uuid_assign_active |= uuid_assign_deleted
                q_del = delete(AssocCollectionDocument).where(
                    AssocCollectionDocument.uuid.in_(uuid_assign_active)
                )
            else:
                detail = "Assignment deleted."
                q_del = (
                    update(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                    .values(deleted=True)
                )

            # DELETED ALREADY EXCLUDED IN NON FORCE CASE
            uuid_collection_wassign_active = set(
                session.execute(
                    select(Collection.uuid)
                    .join(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                ).scalars()
            )
            q_assocs = document.q_select_assignment(
                uuid_collection_wassign_active,
                exclude_deleted=False,
            )
            assocs = list(session.execute(q_assocs).scalars())

            event_common: Dict[str, Any] = dict(
                api_origin="DELETE /assignments/documents/<uuid>",
                api_version=__version__,
                detail=detail,
                uuid_user=user.uuid,
                kind=KindEvent.delete,
            )

            session.add(
                event := Event(
                    **event_common,
                    kind_obj=KindObject.document,
                    uuid_obj=document.uuid,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=KindObject.collection,
                            uuid_obj=assoc.uuid_collection,
                            children=[
                                Event(
                                    **event_common,
                                    kind_obj=KindObject.assignment,
                                    uuid_obj=assoc.uuid,
                                )
                            ],
                        )
                        for assoc in assocs
                    ],
                )
            )
            session.execute(q_del)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def delete_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocument,
        force: args.QueryForce = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            print("========================================================")
            user, _, (collection,) = Access(session, token).assignment(
                uuid_collection={uuid_collection},
                uuid_document=uuid_document,
                level=Level.view,
            )
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, collection, uuid_document, literal_column("uuid")
            )
            if force:
                detail = "Assignment force deleted."
                uuid_assign_active |= uuid_assign_deleted
                q_del = delete(AssocCollectionDocument).where(
                    AssocCollectionDocument.uuid.in_(uuid_assign_active)
                )
            else:
                detail = "Assignment deleted."
                q_del = (
                    update(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                    .values(deleted=True)
                )

            # NOTE: DO NOT EXCLUDED DELETED VALUES IN `q_select_assignment`.
            #       DELETED VALUES MAY EXIST AND REQUIRE FORCE DELETION.
            uuid_docs_active = set(
                session.execute(
                    select(Document.uuid)
                    .join(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                ).scalars()
            )
            q_assocs = collection.q_select_assignment(
                uuid_docs_active, exclude_deleted=False
            )
            util.sql(session, q_assocs)
            assocs = list(session.execute(q_assocs).scalars())

            # Create events
            event_common = dict(
                api_origin="DELETE /assignments/collections/<uuid>",
                api_version=__version__,
                kind=KindEvent.delete,
                uuid_user=user.uuid,
                detail=detail,
            )
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=collection.uuid,
                children=[
                    session.refresh(assoc)
                    or Event(
                        **event_common,
                        kind_obj=KindObject.document,
                        uuid_obj=assoc.uuid_document,
                        children=[
                            Event(
                                **event_common,
                                kind_obj=KindObject.assignment,
                                uuid_obj=assoc.uuid,
                            )
                        ],
                    )
                    for assoc in assocs
                ],
            )

            session.add(event)
            session.execute(q_del)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def post_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollection,
    ) -> EventSchema:
        with sessionmaker() as session:
            (user, (document,), collections) = Access(session, token).assignment(
                uuid_document={uuid_document},
                uuid_collection=uuid_collection,
                level=Level.view,
            )

            # Collection uuids for existing and deleted assignments
            lit = literal_column("uuid_collection")
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, document, uuid_collection, lit
            )

            if uuid_assign_deleted:
                raise HTTPException(
                    400,
                    detail=dict(
                        uuid_user=user.uuid,
                        uuid_document=document.uuid,
                        uuid_collection=list(uuid_assign_deleted),
                        msg="Assignments must be hard deleted to re-`POST`.",
                    ),
                )

            assocs = [
                AssocCollectionDocument(
                    id_collection=collection.id,
                    id_document=document.id,
                )
                for collection in collections
                if collection.uuid not in uuid_assign_active
            ]
            session.add_all(assocs)
            session.commit()

            event_common = dict(
                api_origin="POST /assignments/document/<uuid>",
                api_version=__version__,
                kind=KindEvent.create,
                uuid_user=token["uuid"],
                detail="Assignment created.",
            )
            event = Event(
                **event_common,
                kind_obj=KindObject.document,
                uuid_obj=document.uuid,
                children=[
                    session.refresh(assoc)
                    or Event(
                        **event_common,
                        kind_obj=KindObject.collection,
                        uuid_obj=assoc.uuid_collection,
                        children=[
                            Event(
                                kind_obj=KindObject.assignment,
                                uuid_obj=assoc.uuid,
                                **event_common,
                            )
                        ],
                    )
                    for assoc in assocs
                ],
            )

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def post_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocument,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, documents, (collection,) = Access(session, token).assignment(
                uuid_collection={uuid_collection},
                uuid_document=uuid_document,
                level=Level.view,
            )

            uuid_doc_deleted, uuid_doc_active = cls.split_assignments(
                session,
                collection,
                uuid_document,
                literal_column("uuid_document"),
            )
            if uuid_doc_deleted:
                raise HTTPException(
                    400,
                    detail=dict(
                        uuid_user=user.uuid,
                        uuid_document=list(uuid_doc_deleted),
                        uuid_collection=collection.uuid,
                        msg="Assignments must be hard deleted to re-`POST`.",
                    ),
                )

            # Create
            assocs = list(
                AssocCollectionDocument(
                    id_document=document.id,
                    id_collection=collection.id,
                )
                for document in documents
                if document.uuid not in uuid_doc_active
            )
            session.add_all(assocs)
            session.commit()

            # Create events
            event_common = dict(
                api_origin="POST /assignments/collections/<uuid>",
                api_version=__version__,
                kind=KindEvent.create,
                uuid_user=token["uuid"],
                detail="Assignment created.",
            )
            session.add(
                event := Event(
                    **event_common,
                    kind_obj=KindObject.collection,
                    uuid_obj=collection.uuid,
                    children=[
                        session.refresh(assoc)
                        or Event(
                            **event_common,
                            kind_obj=KindObject.document,
                            uuid_obj=assoc.uuid_document,
                            children=[
                                Event(
                                    **event_common,
                                    kind_obj=KindObject.assignment,
                                    uuid_obj=assoc.uuid,
                                )
                            ],
                        )
                        for assoc in assocs
                    ],
                )
            )
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def get_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocumentOptional = None,
    ) -> List[AssignmentSchema]:
        with sessionmaker() as session:
            _, collection = Access(session, token).collection(
                uuid_collection=uuid_collection
            )
            q = collection.q_select_assignment(
                uuid_document,
                exclude_deleted=True,
            )
            res = session.execute(q).scalars()

            return list(AssignmentSchema.model_validate(item) for item in res)

    @classmethod
    def get_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollectionOptional = None,
    ) -> List[AssignmentSchema]:
        with sessionmaker() as session:
            _, document = Access(session, token, uuid_document).document(
                uuid_document, level=Level.view
            )
            q = document.q_select_assignment(
                uuid_collection,
                exclude_deleted=True,
            )

            res = session.execute(q).scalars()
            return list(AssignmentSchema.model_validate(item) for item in res)
