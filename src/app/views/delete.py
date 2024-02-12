from http import HTTPMethod
from typing import Any, Dict, List, Set, Tuple, overload

from app import __version__
from app.auth import Token
from app.depends import DependsToken
from app.models import (
    Assignment,
    AssocCollectionDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Edit,
    Event,
    KindEvent,
    KindObject,
    Resolvable,
    ResolvableMultiple,
    ResolvableSingular,
    User,
)
from app.schemas import EventSchema
from app.views.access import WithAccess
from app.views.base import Data
from sqlalchemy import delete, literal_column, select, union, update
from sqlalchemy.orm import Session


class Delete(WithAccess):
    """Perform deletions."""

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_document: ResolvableMultiple[Document],
        *,
        resolve_user: User | str | None = None,
    ) -> Event:

        session = self.session
        user = User.resolve(session, resolve_user or self.token.uuid)
        collection = Collection.resolve(session, resolve_collection)
        uuid_document: Set[str] = Document.resolve_uuid(session, resolve_document)

        # NOTE: Ignore entries that are already deletd.
        uuid_assign_deleted, uuid_assign_active = Assignment.split(
            session, collection, uuid_document
        )
        if self.force:
            # detail = detail or "Assignment force deleted."
            uuid_assign_active |= uuid_assign_deleted
            q_del = delete(AssocCollectionDocument).where(
                AssocCollectionDocument.uuid.in_(uuid_assign_active)
            )
        else:
            # detail = detail or "Assignment deleted."
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
        event_common = dict(
            api_version=__version__,
            kind=KindEvent.delete,
            uuid_user=user.uuid,
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
        # data: Data[ResolvableAssignmentDocument],
        # api_origin: str | None = None,
        # detail: str | None = None,
    ) -> Event:

        # document: Document = Document.resolve(session, resolve_document)
        # uuid_collection: Set[str] = Collection.resolve_uuid(
        #     session,
        #     resolve_collection,
        # )
        session = self.session
        user = User.resolve(session, resolve_user or self.token.uuid)
        document: Document = Document.resolve(session, resolve_document)
        uuid_collection: Set[str] = Collection.resolve_uuid(
            session,
            resolve_collection,
        )

        uuid_assign_deleted, uuid_assign_active = Assignment.split(
            self.session, document, uuid_collection
        )

        if self.force:
            # detail = detail or "Assignment force deleted."
            uuid_assign_active |= uuid_assign_deleted
            q_del = delete(AssocCollectionDocument).where(
                AssocCollectionDocument.uuid.in_(uuid_assign_active)
            )
        else:
            # detail = detail or "Assignment deleted."
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

        event_common: Dict[str, Any] = self.event_common
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

    # @overload
    # def assignment(
    #     self,
    #     resolve_source: ResolvableSingular[Document],
    #     resolve_target: ResolvableMultiple[Collection],
    #     *,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # @overload
    # def assignment(
    #     self,
    #     resolve_source: ResolvableSingular[Collection],
    #     resolve_target: ResolvableMultiple[Document],
    #     *,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # def assignment(
    #     self,
    #     resolve_source: ResolvableSingular[Collection] | ResolvableSingular[Document],
    #     resolve_target: ResolvableMultiple[Document] | ResolvableMultiple[Collection],
    #     *,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Event:
    #     kwargs: Dict[str, Any] = dict(resolve_user=resolve_user)
    #     match resolve_source:
    #         case Collection() as collection:
    #             return self.assignment_collection(
    #                 collection, resolve_target, **kwargs  # type: ignore
    #             )
    #         case Document() as document:
    #             return self.assignment_document(
    #                 document, resolve_target, **kwargs  # type: ignore
    #             )
    #         case _:
    #             raise ValueError("Invalid `resolve_source`.")
    #
    # def collection(
    #     self,
    #     resolve_collection: ResolvableSingular[Collection],
    #     *,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Event:
    #
    #     session = self.session
    #     collection = Collection.resolve(session, resolve_collection)
    #     user = User.resolve(session, resolve_user or self.token.uuid)
    #
    #     # Find docs
    #     p = select(Document.uuid).join(AssocCollectionDocument)
    #     p = p.where(AssocCollectionDocument.id_collection == collection.id)
    #     q = select(literal_column("uuid"))
    #     q = union(q.select_from(collection.q_select_documents()), p)
    #     uuid_document = set(session.execute(q).scalars())
    #
    #     # Delete assigns and get events before deletion.
    #     event_assign = self.assignment_collection(
    #         collection,
    #         uuid_document,
    #         resolve_user=user,
    #     )
    #
    #     if self.force:
    #         session.delete(collection)
    #     else:
    #         collection.deleted = True
    #         session.add(collection)
    #
    #     # Create event
    #     session.add(
    #         event := Event(
    #             **self.event_common,
    #             uuid_obj=collection.uuid,
    #             children=[event_assign],
    #             # detail=detail,
    #         )
    #     )
    #     session.commit()
    #     session.refresh(event)
    #     return event
    #
    # # ----------------------------------------------------------------------- #
    # # Grants
    # def grant_user(
    #     self,
    #     resolve_user: ResolvableSingular[User],
    #     resolve_documents: ResolvableMultiple[Document],
    #     *,
    #     token_user: ResolvableSingular[User],
    # ) -> Event: ...
    #
    # def grant_document(
    #     self,
    #     resolve_document: ResolvableSingular[Document],
    #     resolve_users: ResolvableMultiple[User],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # def grant(
    #     self,
    #     resolve_target: ResolvableSingular[Document] | ResolvableSingular[User],
    #     resolve_source: ResolvableMultiple[User] | ResolvableMultiple[Document],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
    # # Collections
    #
    # def document(
    #     self,
    #     resolvable_document: Resolvable[Document],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
    # # Edits
    # #
    #
    # def edit(
    #     self,
    #     resolvable_edit: Resolvable[Edit],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
    # # Users
    # def user(
    #     self,
    #     resolvable_user: Resolvable[Document],
    #     *,
    #     token_user: ResolvableSingular[User],
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
