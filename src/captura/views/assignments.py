# =========================================================================== #
from typing import List

from pydantic import TypeAdapter
from sqlalchemy import func, select
from sqlalchemy.sql.expression import false

# --------------------------------------------------------------------------- #
from captura.depends import DependsAccess, DependsCreate, DependsDelete
from captura.models import Assignment, Collection, Document, Level
from captura.schemas import (
    AsOutput,
    AssignmentCreateSchema,
    AssignmentSchema,
    EventSchema,
    OutputWithEvents,
    mwargs,
)
from captura.views import args
from captura.views.base import BaseView, OpenApiResponseUnauthorized, OpenApiTags

OpenApiResponseAssignment = {
    **OpenApiResponseUnauthorized,
    403: dict(
        model=dict,
        description=(
            "Raised when a user does not own any of the collections in "
            "question or when a user cannot at least view a document in "
            "question."
        ),
    ),
}


# NOTE: Should mirron :class:`GrantView`. Updates not supported, scoped by
#       collection.
class DocumentAssignmentView(BaseView):
    adapter = TypeAdapter(List[AssignmentSchema])

    view_router_args = dict(
        tags=[OpenApiTags.assignments], responses=OpenApiResponseAssignment
    )

    view_routes = dict(
        delete_assignments_document=dict(
            url="/{uuid_document}",
            name="Remove Document from Collections by Deleting Assignments",
        ),
        post_assignments_document=dict(
            url="/{uuid_document}",
            name="Add Document to Collections by Creating Assignments",
        ),
        get_assignments_document=dict(
            url="/{uuid_document}",
            name="Read Assignments of Document to Collections",
        ),
    )

    @classmethod
    def delete_assignments_document(
        cls,
        delete: DependsDelete,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollection,
    ) -> OutputWithEvents[List[AssignmentSchema]]:
        """Remove document from some collections.

        Collection owners should remove this document from their collection
        using ``DELETE /assignments/collections/{uuid_collection}``.

        All that is required is a token and document ownership.

        Collection ownership is not enforced here so that the document owner
        have the final say in which collections their document can be included.

        Document ownership is enforced since only document owners can
        reject/accept their document from being part of a particular collection.
        """
        data = delete.access.d_assignment_document(
            uuid_document,
            uuid_collection,  # type: ignore
            allow_public=False,
            validate_collections=False,
            level=Level.own,
            exclude_deleted=not delete.force,
        )

        assignments, events = list(), list()
        if len(data.data.collections):
            delete.assignment_document(data)
            assignments = cls.adapter.validate_python(data.data.assignments.values())
            data.commit(delete.session)
            events.append(EventSchema.model_validate(data.event))

        return mwargs(
            OutputWithEvents[List[AssignmentSchema]],
            events=events,
            data=assignments,
        )

    @classmethod
    def post_assignments_document(
        cls,
        create: DependsCreate,
        uuid_document: args.PathUUIDDocument,
        uuid_collection: args.QueryUUIDCollection,
    ) -> OutputWithEvents[List[AssignmentSchema]]:
        """Add this document to collections.

        All that is required is a token and document ownership.

        Collection ownership is not enforced here so that the document owner
        have the final say in which collections their document can be included.

        Document ownership is enforced since only document owners can
        reject/accept their document from being part of a particular collection.
        """
        data = create.access.d_assignment_document(
            uuid_document,
            uuid_collection,  # type: ignore
            allow_public=False,
            level=Level.own,
            validate_collections=False,
        )
        create.create_data = AssignmentCreateSchema()
        data_final = create.assignment_document(data)
        data_final.commit(create.session)

        assignments = data_final.data.assignments
        return mwargs(
            OutputWithEvents[List[AssignmentSchema]],
            data=cls.adapter.validate_python(assignments.values()),
            events=[EventSchema.model_validate(data_final.event)],
        )

    @classmethod
    def get_assignments_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
        *,
        uuid_collection: args.QueryUUIDCollectionOptional = None,
        limit: int | None = None,
        randomize: bool = False,
    ) -> AsOutput[List[AssignmentSchema]]:
        """Read the collections to which this document belongs.

        For non-private documents all that is required is a token.
        For private documents a grant of level view is required.
        """

        # NOTE: Check document access first. Then data is constructed later.
        #       This is done because get the collections can be expensive due
        #       to `ORDER BY RANDOM()`.
        document = access.document(
            uuid_document,
            allow_public=True,
            level=Level.view,
            return_data=False,
        )

        q = (
            select(Collection)
            .join(Assignment)
            .where(
                Assignment.id_document == document.id,
                Assignment.deleted == false(),
                Collection.deleted == false(),
            )
        )
        if uuid_collection is not None:
            q = q.where(Collection.uuid.in_(uuid_collection))
        if randomize:
            q = q.order_by(func.random())
        if limit:
            q = q.limit(limit)

        collections = tuple(access.session.scalars(q))
        data = access.d_assignment_document(
            document,
            collections,
            level=Level.view,
            validate_document=False,  # NOTE: Already validated.
            validate_collections=False,
            all_collections=False,
            allow_public=True,
        )

        # NOTE: So that the radomness of the collections is passed down here.
        assignments = tuple(
            ass
            for collection in collections
            if (ass := data.data.assignments.get(collection.uuid)) is not None
        )
        return mwargs(
            AsOutput[List[AssignmentSchema]],
            data=cls.adapter.validate_python(assignments),
        )


class CollectionAssignmentView(BaseView):
    adapter = TypeAdapter(List[AssignmentSchema])

    view_routes = dict(
        delete_assignments_collection=dict(
            url="/{uuid_collection}",
            description="Remove Documents from Collection (by Deleting Assignments)",
        ),
        post_assignments_collection=dict(
            url="/{uuid_collection}",
            description="Add Documents to Collection (by Creating Assignments)",
        ),
        get_assignments_collection=dict(
            url="/{uuid_collection}",
            description="Read Documents for Collection.",
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.assignments], responses=OpenApiResponseAssignment
    )

    @classmethod
    def delete_assignments_collection(
        cls,
        delete: DependsDelete,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocument,
    ) -> OutputWithEvents[List[AssignmentSchema]]:
        data = delete.access.d_assignment_collection(
            uuid_collection,
            uuid_document,  # type: ignore
            allow_public=False,
            level=Level.own,
            validate_documents=False,
        )

        assignments, events = list(), list()
        if len(data.data.documents):
            delete.assignment_collection(data)
            assignments = cls.adapter.validate_python(data.data.assignments.values())
            data.commit(delete.session)
            events.append(EventSchema.model_validate(data.event))

        return mwargs(
            OutputWithEvents[List[AssignmentSchema]],
            events=events,
            data=assignments,
        )

    @classmethod
    def post_assignments_collection(
        cls,
        create: DependsCreate,
        uuid_collection: args.PathUUIDCollection,
        uuid_document: args.QueryUUIDDocument,
    ) -> OutputWithEvents[List[AssignmentSchema]]:
        data = create.access.d_assignment_collection(
            uuid_collection,
            uuid_document,  # type: ignore
            level=Level.view,
            allow_public=False,
            validate_documents=False,
        )
        create.create_data = AssignmentCreateSchema()
        data_final = create.assignment_collection(data)
        data_final.commit(create.session)

        return mwargs(
            OutputWithEvents[List[AssignmentSchema]],
            data=cls.adapter.validate_python(data_final.data.assignments.values()),
            events=[EventSchema.model_validate(data_final.event)],
        )

    @classmethod
    def get_assignments_collection(
        cls,
        access: DependsAccess,
        uuid_collection: args.PathUUIDCollection,
        *,
        uuid_document: args.QueryUUIDDocumentOptional = None,
        limit: int | None = None,
        randomize: bool = False,
    ) -> AsOutput[List[AssignmentSchema]]:
        collection = access.collection(uuid_collection, return_data=False)
        q = (
            select(Document)
            .join(Assignment)
            .where(
                Document.deleted == false(),
                Assignment.deleted == false(),
                Assignment.id_collection == collection.id,
            )
        )
        if uuid_document is not None:
            q = q.where(Document.uuid.in_(uuid_document))
        if randomize:
            q = q.order_by(func.random())
        if limit:
            q = q.limit(limit)

        documents = tuple(access.session.scalars(q))
        data = access.d_assignment_collection(
            collection,
            documents,
            validate_documents=False,
        )
        assignments = tuple(
            ass
            for document in documents
            if (ass := data.data.assignments.get(document.uuid)) is not None
        )
        return mwargs(
            AsOutput[List[AssignmentSchema]],
            data=cls.adapter.validate_python(assignments),
        )
