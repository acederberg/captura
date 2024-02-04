from functools import cached_property
from http import HTTPMethod
from typing import Any, Dict, Set, Tuple, overload

from app import __version__
from app.auth import Token
from app.models import (
    Assignment,
    Collection,
    Document,
    Event,
    KindEvent,
    KindObject,
    ResolvableMultiple,
    ResolvableSingular,
    Tables,
    User,
)
from app.schemas import (
    AssignmentSchema,
    CollectionPatchSchema,
    CollectionPostSchema,
    DocumentPostSchema,
    EventSchema,
    PostUserSchema,
    UserUpdateSchema,
)
from app.views.base import BaseController, ForceController
from app.views.delete import Delete
from fastapi import HTTPException
from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session


class Upsert(ForceController):

    _delete: Delete | None

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        force: bool = True,
        delete: Delete | None = None,
    ):
        super().__init__(session, token, method, force=force)
        self._delete = delete

    @cached_property
    def event_common(self) -> Dict[str, Any]:
        event_common = dict(
            uuid_user=self.token.uuid,
            api_version=__version__,
            kind=KindEvent.create,
        )
        return event_common

    @property
    def delete(self) -> Delete:
        if not self.force:
            msg = "`delete` is not available when `force` is not `True`."
            raise ValueError(msg)
        elif self._delete is not None:
            return self._delete

        delete = self.then(Delete, force=self.force)
        self._delete = delete
        return delete

    def user(
        self,
        resolvable_user: ResolvableSingular[User],
        data: UserUpdateSchema | PostUserSchema,
    ) -> Event: ...

    def collection(
        self,
        resolvable_collection: ResolvableSingular[Collection],
        data: CollectionPatchSchema | CollectionPostSchema,
    ) -> Event: ...

    def assignment_try_force(
        self,
        source: Collection | Document,
        uuid_target: Set[str],
        *,
        api_origin: str | None = None,
        detail: str | None = None,
    ) -> Tuple[None | Event, Set[str]]:

        uuid_assign_deleted, uuid_assign_active = self.split_assignment_uuids(
            source, uuid_target
        )
        uuid_target_deleted, uuid_target_active = Assignment.split(
            self.session, source, uuid_target
        )

        # If force, delete existing entries.
        event: Event | None = None
        if self.force:
            event = self.delete.assignment(
                source,
                uuid_target_deleted,
                resolve_user=self.token_user,
                api_origin=api_origin,
                detail=detail,
            )
            uuid_target_deleted = set()

        return event, uuid_target_active

    # NOTE: No Patch
    def assignment_document(
        self,
        resolvable_document: ResolvableSingular[Document],
        resolvable_collections: ResolvableMultiple[Collection],
        *,
        detail: str = "Assignment created.",
        api_origin: str = "POST /assignments/document/<uuid>",
    ) -> Event:

        if self.method != HTTPMethod.POST:
            raise HTTPException(405)

        token_user, session = self.token_user, self.session

        document = Document.resolve(session, resolvable_document)
        collections = Collection.resolve(session, resolvable_collections)

        # NOTE: Gets rejected when deleted and force.
        uuid_collection = Collection.resolve_uuid(
            session,
            resolvable_collections,
        )
        event_force, uuid_collection_existing = self.assignment_try_force(
            document, uuid_collection, detail=detail, api_origin=api_origin
        )

        assocs = [
            Assignment(id_collection=collection.id, id_document=document.id)
            for collection in collections
            if collection.uuid not in uuid_collection_existing
        ]

        session.add_all(assocs)
        session.commit()

        event_common = dict(
            **self.event_common,
            api_origin=api_origin,
            detail=detail,
            uuid_user=token_user.uuid,
        )
        session.add(
            event := Event(
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
        )
        if event_force is not None:
            event.children.append(event_force)

        session.commit()
        session.refresh(event)

        return event

    # NOTE: No Patch
    def assignment_collection(
        self,
        resolvable_collection: ResolvableSingular[Collection],
        resolvable_documents: ResolvableMultiple[Document],
        *,
        detail: str = "Assignment created.",
        api_origin: str = "POST /assignments/collections/<uuid>",
    ) -> Event:

        if self.method != HTTPMethod.POST:
            raise HTTPException(405)

        session, token_user = self.session, self.token_user
        collection = Collection.resolve(session, resolvable_collection)

        documents = Document.resolve(session, resolvable_documents)
        uuid_document = Document.resolve_uuid(session, documents)

        event_force, uuid_document_existing = self.assignment_try_force(
            collection, uuid_document, detail=detail, api_origin=api_origin
        )

        # uuid_assign_deleted, uuid_assign_deleted = self.split_assignment_uuids(
        #     collection, uuid_document
        # )
        #
        # event_cleanup: Event | None = None
        # if self.force:
        #     q_uuid_col_del = (
        #         select(Collection.uuid)
        #         .join(Assignment)
        #         .where(Assignment.uuid.in_(uuid_assign_deleted))
        #     )
        #     uuid_document = set(session.execute(q_uuid_col_del).scalars())
        #     event_cleanup = self.delete.assignment_collection(
        #         collection,
        #         uuid_document,
        #         resolve_user=self.token_user,
        #         api_origin=api_origin,
        #         detail=detail,
        #     )

        # Create
        assocs = list(
            Assignment(
                id_document=document.id,
                id_collection=collection.id,
            )
            for document in documents
            if document.uuid not in uuid_document_existing
        )
        session.add_all(assocs)
        session.commit()

        # Create events
        event_common = dict(
            *self.event_common,
            api_origin=api_origin,
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
        if event_force is not None:
            event.children.append(event_force)

        session.add(event)
        session.commit()
        session.refresh(event)
        return event

    def assignment(
        self,
        resolvable_source: (
            ResolvableSingular[Collection] | ResolvableSingular[Document]
        ),
        resolvable_target: (
            ResolvableMultiple[Document] | ResolvableMultiple[Collection]
        ),
        *,
        detail: str | None = None,
        api_origin: str | None = None,
    ) -> Event:

        kwargs: Dict[str, Any] = dict(detail=detail, api_origin=api_origin)
        match resolvable_source:
            case Collection():
                return self.assignment_collection(
                    resolvable_source,
                    resolvable_target,  # type: ignore
                    **kwargs,
                )
            case Document():
                return self.assignment_document(
                    resolvable_source,
                    resolvable_target,  # type: ignore
                    **kwargs,
                )
            case _:
                raise ValueError()

    # NOTE:
    def document(
        self,
        resolvable_document: ResolvableSingular[Document],
        data: DocumentPostSchema,
    ) -> Event: ...
