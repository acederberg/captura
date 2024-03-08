from http import HTTPMethod
from typing import Any, Dict, List, Set, Tuple

from app import __version__, util
from app.controllers.access import Access
from app.controllers.create import Create
from app.controllers.delete import Delete
from app.depends import DependsSessionMaker, DependsToken
from app.models import (Assignment, AssocCollectionDocument,
                        ChildrenAssignment, Collection, Document, Event,
                        KindEvent, KindObject, Level, User)
from app.schemas import AssignmentSchema, EventSchema
from app.views import args
from app.views.base import (BaseView, OpenApiResponseCommon,
                            OpenApiResponseUnauthorized, OpenApiTags)
from fastapi import HTTPException
from sqlalchemy import delete, literal_column, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true

OpenApiResponseAssignment = {
    **OpenApiResponseUnauthorized,
    403: dict(
        model=dict,
        description=(
            "Raised when a user does not own any of the collections in "
            "question or when a user cannot at least view a document in "
            "question."
        )
    )
}


# NOTE: Should mirron :class:`GrantView`. Updates not supported, scoped by
#       collection.
class DocumentAssignmentView(BaseView):
    view_router_args = dict(
        tags=[OpenApiTags.assignments],
        responses= OpenApiResponseAssignment)

    view_routes = dict(
        delete_assignment_document=dict(
            url="/{uuid_document}",
            name="Remove Document from Collections by Deleting Assignments"
        ),
        post_assignment_document=dict(
            url="/{uuid_document}",
            name="Add Document to Collections by Creating Assignments",
        ),
        get_assignment_document=dict(
            url="/{uuid_document}",
            name="Read Assignments of Document to Collections",
        ),
    )

    @classmethod
    def delete_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollection,
        force: args.QueryForce = False,
    ) -> EventSchema:
        """
        """
        with sessionmaker() as session:
            access = Access(session, token, HTTPMethod.DELETE)
            collection, documents = access.assignment_document(
                uuid_document,
                resolve_collections=uuid_collection,
                level=Level.own,
                exclude_deleted=False,
            )
            delete = access.then(Delete, force=force)
            event = delete.assignment_document(
                collection,
                documents,
                resolve_user=access.token_user,
            )
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
            access = Access(session, token, HTTPMethod.POST)
            document, collections = access.assignment_document(
                uuid_document,
                uuid_collection,
            )

            upsert = access.then(Create)
            event = upsert.assignment_document(document, collections)
            return EventSchema.model_validate(event)

    @classmethod
    def get_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollectionOptional = None,
    ) -> List[AssignmentSchema]:
        with sessionmaker() as session:
            access = Access(session, token, HTTPMethod.GET)
            document = access.document(uuid_document)
            q = document.q_select_assignment(
                uuid_collection,
                exclude_deleted=True,
            )

            res = session.execute(q).scalars()
            return list(AssignmentSchema.model_validate(item) for item in res)

class CollectionAssignmentView(BaseView):
    view_routes = dict(
        delete_assignment_collection=dict(
            url="/{uuid_collection}",
            description="Remove Documents from Collection (by Deleting Assignments)",
        ),
        post_assignment_collection=dict(
            url="/{uuid_collection}",
            description="Add Documents to Collection (by Creating Assignments)",
        ),
        get_assignment_collection=dict(
            url="/{uuid_collection}",
            description="Read Documents for Collection.",
        )
    )
    view_router_args = dict(
        tags=[OpenApiTags.assignments],
        responses=OpenApiResponseAssignment
    )

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
            # Users need to be able to access all for force deletion
            access = Access(session, token, HTTPMethod.DELETE)
            documents, collections = access.assignment_collection(
                uuid_collection,
                resolve_documents=uuid_document,
                exclude_deleted=False,
            )
            delete = access.then(Delete)
            event = delete.assignment_collection(
                documents,
                collections,
                resolve_user=access.token_user,
            )
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
            access = Access(session, token, HTTPMethod.POST)
            collection, documents = access.assignment_collection(
                uuid_collection,
                uuid_document,
            )

            upsert = access.then(Create)
            event = upsert.assignment_collection(collection, documents)
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
            access = Access(session, token, HTTPMethod.GET)
            collection = access.collection(uuid_collection)
            q = collection.q_select_assignment(
                uuid_document,
                exclude_deleted=True,
            )
            res = session.execute(q).scalars()

            return list(AssignmentSchema.model_validate(item) for item in res)

