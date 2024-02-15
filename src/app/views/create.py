import secrets
from functools import cached_property
from http import HTTPMethod
from typing import Any, Dict, Set, Tuple, TypeVar, overload

from app import __version__
from app.auth import Token
from app.models import (Assignment, Collection, Document, Event, KindEvent,
                        KindObject, ResolvableMultiple, ResolvableSingular,
                        ResolvableSourceAssignment, ResolvableTargetAssignment,
                        Tables, User)
from app.schemas import (AssignmentSchema, CollectionPatchSchema,
                         CollectionPostSchema, DocumentPostSchema, EventSchema,
                         PostUserSchema, UserUpdateSchema)
from app.views.access import WithAccess, with_access
from app.views.base import (Data, ResolvedAssignmentCollection,
                            ResolvedAssignmentDocument, ResolvedCollection,
                            ResolvedDocument, ResolvedEdit,
                            ResolvedGrantDocument, ResolvedGrantUser,
                            ResolvedUser)
from app.views.delete import DataResolvedAssignment, Delete, WithDelete
from fastapi import HTTPException
from sqlalchemy import Delete, Update, literal_column, select
from sqlalchemy.orm import Session

T_Upsert = TypeVar(
    "T_Upsert",
    ResolvedAssignmentCollection,
    ResolvedAssignmentCollection,
)


class Upsert(WithDelete):

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]: ...

    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]: ...

    # NOTE:
    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]: ...

    def edit(self, data: Data[ResolvedEdit],) -> Data[ResolvedEdit]: ...

    def assignment_try_force(
        self,
        data: DataResolvedAssignment,
    ) -> Set[str]:
        """Symetrically handle forced creation.

        When :attr:`force` is ``True``, lingering assignments staged for
        deletion will be cleaned up by :attr:`delete`. Otherwise, if
        :param:`data` specified exising assignments, an error will be raised.

        :returns: The active target ids that do not yet have an assignment to
            their source. The requirement that they be active means that doing
            the same `POST` twice should be indempotent.
        """
        # If force, delete existing entries.  Defer to the delete controller.
        if self.force:
            _ = self.delete.assignment(data)

        source: Collection | Document = data.data.source  # type: ignore[reportGeneralTypeIssues]
        uuid_target: Set[str] = data.data.uuid_target  # type: ignore[reportGeneralTypeIssues]

        # NOTE: Should be done only after potential force deletion.
        uuid_target_deleted, uuid_target_active = Assignment.split(
            self.session,
            source,
            uuid_target,
            select_parent_uuids=True,
        )
        if uuid_target_deleted:
            msg = "Some targets have existing assignments awaiting cleanup. "
            msg += "Try this request again with `force=true`."
            raise HTTPException(
                400,
                detail=dict(
                    msg=msg,
                    uuid_target=uuid_target_deleted,
                    uuid_source=source.uuid,
                ),
            )

        return uuid_target_active

    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]:

        # NOTE: Gets rejected when deleted and force.
        session = self.session
        uuid_collection_assignable = self.assignment_try_force(data)
        document = data.data.document
        collections = data.data.collections

        # NOTE: uuids generate here so only one commit
        assocs = [
            Assignment(
                id_collection=collection.id,
                id_document=document.id,
                uuid=secrets.token_urlsafe(8),
            )
            for collection in collections
            if collection.uuid in uuid_collection_assignable
        ]
        session.add_all(assocs)

        event_common = dict(**self.event_common, kind=KindEvent.create)
        session.add(
            event := Event(
                **event_common,
                kind_obj=KindObject.document,
                uuid_obj=data.data.document.uuid,
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
        )
        if data.event is not None:
            event.children.append(data.event)
        data.event = event

        session.commit()
        session.refresh(event)

        return data

    def assignment_collection(
        self, data: Data[ResolvedAssignmentCollection]
    ) -> Data[ResolvedAssignmentCollection]:

        session = self.session
        uuid_document_assignable = self.assignment_try_force(data)

        collection = data.data.collection
        documents = data.data.documents

        # Create
        assocs = list(
            Assignment(
                uuid=secrets.token_urlsafe(8),
                id_document=document.id,
                id_collection=collection.id,
            )
            for document in documents
            if document.uuid in uuid_document_assignable
        )
        session.add_all(assocs)

        # Create events
        event_common = dict(*self.event_common, kind=KindEvent.create)
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
        session.commit()
        session.refresh(event)
        if data.event is not None:
            event.children.append(data.event)
        data.event = event

        return data

    def grant_user(self, data: Data[ResolvedGrantUser]) -> Data[ResolvedGrantUser]:

        ...

    def grant_document(self, data: Data[ResolvedGrantDocument]) -> Data[ResolvedGrantDocument]:
        ...
