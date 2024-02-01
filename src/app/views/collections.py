from typing import Any, Dict, List, Sequence, Set, Tuple, overload

from app import __version__, util
from app.depends import DependsSessionMaker, DependsToken, DependsTokenOptional
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
from app.schemas import (
    AssignmentSchema,
    CollectionPatchSchema,
    CollectionPostSchema,
    CollectionSchema,
    CollectionSearchSchema,
    DocumentMetadataSchema,
    EventSchema,
)
from app.views import args
from app.views.base import BaseView
from fastapi import Depends, HTTPException
from sqlalchemy import delete, literal_column, select, union, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true


class CollectionView(BaseView):
    """Routes for collection CRUD and metadata."""

    view_routes = dict(
        get_collection="/{uuid_collection}",
        get_collections="",
        get_collection_documents="/{uuid_collection}/documents",
        delete_collection="/{uuid_collection}",
        patch_collection="/{uuid_collection}",
        post_collection="",
    )

    @classmethod
    def get_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
    ) -> CollectionSchema:
        with sessionmaker() as session:
            user, collection = cls.verify_access(session, token, uuid_collection)
            return CollectionSchema.model_validate(collection)

    @classmethod
    def get_collections(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsTokenOptional = None,
        param: CollectionSearchSchema = Depends(),
    ) -> List[CollectionSchema]:
        with sessionmaker() as session:
            if token:
                _ = User.if_exists(session, token["uuid"]).check_not_deleted(410)

            q = Collection.q_search(
                token.get("uuid") if token is not None else None,
                param.uuid_collection,
                exclude_deleted=True,
                name_like=param.name_like,
                description_like=param.description_like,
                all_=True,
                session=session,
            )
            return list(
                CollectionSchema.model_validate(item) for item in session.execute(q)
            )

    @classmethod
    def get_collection_documents(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocumentOptional = None,
    ) -> List[DocumentMetadataSchema]:
        """Return UUIDS for the documents."""

        with sessionmaker() as session:
            _, collection = cls.verify_access(session, token, uuid_collection)
            documents = list(
                session.execute(
                    collection.q_select_documents(
                        uuid_document,
                        exclude_deleted=True,
                    ),
                ).scalars()
            )
            return documents

    @classmethod
    def delete_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        restore: bool = False,
    ) -> None:  # EventSchema:
        event_common = dict(
            api_version=__version__,
            api_origin="DELETE /collections/<uuid>",
            kind=KindEvent.delete,
            uuid_user=token["uuid"],
            detail=f"Collection {'restored' if restore else 'deleted'}.",
        )
        with sessionmaker() as session:
            collection = Collection.if_exists(
                session, uuid_collection
            ).check_not_deleted()
            user = (
                User.if_exists(session, token["uuid"])
                .check_not_deleted(410)
                .check_can_access_collection(collection)
            )
            if user.id != collection.id_user:
                raise HTTPException(
                    403,
                    detail=dict(
                        msg="User can only delete their own collections.",
                        uuid_user=token["uuid"],
                        uuid_collection=uuid_collection,
                    ),
                )

            collection.deleted = not restore
            session.add(collection)
            session.commit()

            p = select(Document.uuid).join(AssocCollectionDocument)
            p = p.where(AssocCollectionDocument.id_collection == collection.id)
            q = select(literal_column("uuid"))
            q = union(q.select_from(collection.q_select_documents()), p)
            uuid_document = set(session.execute(q).scalars())

        event_assign_uuid: str | None = None
        if len(uuid_document):
            event_assign_uuid = AssignmentView.delete_assignment(
                sessionmaker,
                token,
                uuid_collection,
                uuid_document,
                restore=restore,
            ).uuid

        with sessionmaker() as session:
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=token["uuid"],
            )

            if event_assign_uuid is not None:
                q = select(Event).where(Event.uuid == event_assign_uuid)
                event_assignment = session.execute(q).scalar()
                assert event_assignment is not None

                detail = event_assignment.detail
                detail = detail.replace(".", " (DELETE /collections/<uuid>).")
                event_assignment.update(
                    session,
                    api_origin=event_common["api_origin"],
                    detail=detail,
                )
                event.children.append(event_assignment)

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def patch_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: args.PathUUIDCollection,
        updates: CollectionPatchSchema = Depends(),
    ):
        """Update collection details or transfer ownership of collection. To
        assign new documents, please `PUT /assign/document/<uuid>."""
        with sessionmaker() as session:
            collection = Collection.if_exists(session, uuid_collection)
            user = User.if_exists(session, token["uuid"])
            if user.id != collection.id_user:
                raise HTTPException(
                    403,
                    detail=dict(
                        msg="User can only delete their own collections.",
                        uuid_user=token["uuid"],
                        uuid_collection=uuid_collection,
                    ),
                )
            event_common = dict(
                uuid_user=user.uuid,
                kind=KindEvent.update,
                api_origin="PATCH /collections/<uuid>",
                api_version=__version__,
            )
            event = Event(
                **event_common,
                uuid_obj=collection.uuid,
                kind_obj=KindObject.collection,
                detail="Collection updated.",
            )

            updates_dict = updates.model_dump()
            uuid_user_target = updates_dict.pop("uuid_user")
            if uuid_user_target is not None:
                target_user = User.if_exists(
                    session,
                    uuid_user_target,
                    msg="Cannot assign collection to user that does not exist.",
                )
                collection.user = target_user
                event.children.append(
                    Event(
                        **event_common,
                        uuid_obj=target_user.uuid,
                        kind_obj=KindObject.user,
                        detail="Collection ownership transfered.",
                    )
                )
                session.add(event)
                session.add(collection)
                session.commit()
                session.refresh(event)
                session.refresh(collection)

            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(collection, key, value)
                event.children.append(
                    Event(
                        **event_common,
                        detail=f"Updated collection {key}.",
                        kind_obj=KindObject.collection,
                    )
                )
            session.add(collection)
            session.commit()

            return EventSchema.model_validate(event)

    @classmethod
    def post_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        data: CollectionPostSchema,
        uuid_document: args.QueryUUIDDocumentOptional = None,
    ) -> EventSchema:
        event_common = dict(
            api_origin="POST /collections",
            api_version=__version__,
            kind=KindEvent.create,
            uuid_user=token["uuid"],
            detail="Collection created.",
        )
        with sessionmaker() as session:
            # Create collection
            user = User.if_exists(session, token["uuid"])
            collection = Collection(**data.model_dump())
            collection.user = user
            session.add(collection)
            session.commit()
            session.refresh(collection)
            uuid_collection = collection.uuid

        uuid_event_assign: str | None = None
        if uuid_document:
            res = AssignmentView.post_assignment(
                sessionmaker,
                token,
                uuid_collection,
                uuid_document,
            ).uuid

        with sessionmaker() as session:
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=collection.uuid,
            )
            if uuid_event_assign is not None:
                event_assignment = session.execute(
                    select(Event).where(Event.uuid == uuid_event_assign)
                ).scalar()
                if event_assignment is None:
                    raise HTTPException(420, detail="Server must be stoned.")
                event.children.append(event_assignment)
                detail = event_assignment.detail
                detail = detail.replace(".", "(POST /collections).")
                event_assignment.update(
                    api_origin=event_common["api_origin"],
                    detail=detail,
                )

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)
