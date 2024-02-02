from typing import Any, Dict, List, Set, Tuple

from app import __version__
from app.depends import DependsToken
from app.models import (
    Assignment,
    AssocCollectionDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Event,
    KindEvent,
    KindObject,
    ResolvableMultiple,
    ResolvableSingular,
    User,
)
from app.schemas import EventSchema
from sqlalchemy import delete, literal_column, select, union, update
from sqlalchemy.orm import Session


class Delete:
    """Perform deletions."""

    token: DependsToken
    session: Session
    force: bool

    def __init__(
        self,
        session: Session,
        token: DependsToken,
        *,
        force: bool = False,
    ):
        self.session = session
        self.token = token
        self.force = force

    @property
    def event_common(self) -> Dict[str, Any]:
        return dict(
            uuid_user=self.token["uuid"],
            api_version=__version__,
            kind=KindEvent.delete,
        )

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_document: ResolvableMultiple[Document],
        *,
        resolve_user: User | str | None = None,
        api_origin: str | None = None,
        detail: str | None = None,
    ) -> Event:

        session = self.session
        user = User.resolve(session, resolve_user or self.token["uuid"])
        collection = Collection.resolve(session, resolve_collection)
        uuid_document: Set[str] = Document.resolve_uuid(session, resolve_document)

        # NOTE: Ignore entries that are already deletd.
        uuid_assign_deleted, uuid_assign_active = Assignment.split(
            session, uuid_document, collection
        )
        if self.force:
            detail = detail or "Assignment force deleted."
            uuid_assign_active |= uuid_assign_deleted
            q_del = delete(AssocCollectionDocument).where(
                AssocCollectionDocument.uuid.in_(uuid_assign_active)
            )
        else:
            detail = detail or "Assignment deleted."
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
        assocs = list(session.execute(q_assocs).scalars())

        # Create events
        origin = api_origin or "DELETE /assignments/collections/<uuid>"
        event_common = dict(
            api_origin=origin,
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

        return event

    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collection: ResolvableMultiple[Collection],
        *,
        resolve_user: User | str | None = None,
        api_origin: str | None = None,
        detail: str | None = None,
    ) -> Event:

        # document: Document = Document.resolve(session, resolve_document)
        # uuid_collection: Set[str] = Collection.resolve_uuid(
        #     session,
        #     resolve_collection,
        # )
        session = self.session
        user = User.resolve(session, resolve_user or self.token["uuid"])
        document: Document = Document.resolve(session, resolve_document)
        uuid_collection: Set[str] = Collection.resolve_uuid(
            session,
            resolve_collection,
        )

        uuid_assign_deleted, uuid_assign_active = Assignment.split(
            self.session, uuid_collection, document
        )

        if self.force:
            detail = detail or "Assignment force deleted."
            uuid_assign_active |= uuid_assign_deleted
            q_del = delete(AssocCollectionDocument).where(
                AssocCollectionDocument.uuid.in_(uuid_assign_active)
            )
        else:
            detail = detail or "Assignment deleted."
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

        origin = api_origin or "DELETE /assignments/documents/<uuid>"
        event_common: Dict[str, Any] = dict(
            api_origin=origin,
            detail=detail,
            **self.event_common,
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
        return event

    def collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        *,
        resolve_user: ResolvableSingular[User] | None = None,
        api_origin: str | None = None,
        detail: str | None = None,
    ) -> Event:
        api_origin = api_origin or "DELETE /collections/<uuid>"
        if detail is None:
            detail = f"Collection {'force ' if self.force else ''}deleted."

        session = self.session
        collection = Collection.resolve(session, resolve_collection)
        user = User.resolve(session, resolve_user or self.token["uuid"])

        # Find docs
        p = select(Document.uuid).join(AssocCollectionDocument)
        p = p.where(AssocCollectionDocument.id_collection == collection.id)
        q = select(literal_column("uuid"))
        q = union(q.select_from(collection.q_select_documents()), p)
        uuid_document = set(session.execute(q).scalars())

        # Delete assigns and get events before deletion.
        event_assign = self.assignment_collection(
            collection,
            uuid_document,
            resolve_user=user,
            api_origin=api_origin,
            detail=detail,
        )

        if self.force:
            session.delete(collection)
        else:
            collection.deleted = True
            session.add(collection)

        # Create event
        session.add(
            event := Event(
                **self.event_common,
                api_origin=api_origin,
                kind_obj=KindObject.collection,
                uuid_obj=collection.uuid,
                children=[event_assign],
                detail=detail,
            )
        )
        session.commit()
        session.refresh(event)
        return event

    def document(self) -> Event: ...

    def user(self) -> Event: ...

    def edit(self) -> Event: ...
