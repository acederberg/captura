# =========================================================================== #
from typing import Annotated, List

from fastapi import Body, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import TypeAdapter

# --------------------------------------------------------------------------- #
from app.controllers.base import Data, ResolvedDocument
from app.depends import (
    DependsAccess,
    DependsCreate,
    DependsDelete,
    DependsRead,
    DependsUpdate,
)
from app.models import Document, Level
from app.schemas import (
    AsOutput,
    DocumentCreateSchema,
    DocumentMetadataSchema,
    DocumentSchema,
    DocumentUpdateSchema,
    EditSchema,
    EventSchema,
    OutputWithEvents,
    TimespanLimitParams,
    mwargs,
)
from app.views import args
from app.views.base import (
    BaseView,
    OpenApiResponseCommon,
    OpenApiResponseDocumentForbidden,
    OpenApiTags,
)

OpenApiResponseDocument = {
    **OpenApiResponseCommon,
    **OpenApiResponseDocumentForbidden,
}


class DocumentSearchView(BaseView):
    view_routes = dict(
        get_recent_documents=dict(
            url="/recent",
            name="Read Recently Editted Document",
        ),
        get_recent_document_edits=dict(
            url="/{uuid_document}/edits",
            name="Read Recents Edits for a Document",
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.documents],
        responses=OpenApiResponseDocument,
    )

    # NOTE: Return the most recently editted
    @classmethod
    def get_recent_documents(
        cls,
        read: DependsRead,
        param: Annotated[TimespanLimitParams, Depends()],
        uuid_documents: args.QueryUUIDDocumentOptional = None,
    ) -> AsOutput[List[DocumentMetadataSchema]]:
        """Recently editted documents."""
        q_documents = Document.q_select_documents(
            read.token_user,
            uuid_documents=uuid_documents,
            limit=param.limit,
            before=param.before_timestamp,
            after=param.after_timestamp,
        )
        # read.token_user.documents
        res = read.session.execute(q_documents)
        documents = tuple(res.scalars())
        return mwargs(
            AsOutput[List[DocumentMetadataSchema]],
            data=TypeAdapter(List[DocumentMetadataSchema]).validate_python(documents),
        )

    @classmethod
    def get_recent_document_edits(
        cls,
        uuid_document: args.PathUUIDDocument,
        read: DependsRead,
        param: Annotated[TimespanLimitParams, Depends()],
    ) -> AsOutput[EditSchema]:
        """Recent edits to a particular document."""

        data: Data[ResolvedDocument] = read.access.d_document(uuid_document)
        (document,) = data.data.documents

        q = document.q_select_edits(
            before=param.before_timestamp,
            after=param.after_timestamp,
            limit=param.limit,
        )
        res = read.session.execute(q)
        edits = tuple(res.scalars())
        return mwargs(
            AsOutput[EditSchema],
            data=TypeAdapter(List[EditSchema]).validate_python(edits),
        )


class DocumentView(BaseView):
    view_routes = dict(
        get_document=dict(
            url="/{uuid_document}",
            name="Get Document JSON",
            responses=OpenApiResponseDocument,
        ),
        get_document_rendered=dict(
            url="/{uuid_document}/rendered",
            name="Get Rendered Document",
            responses=OpenApiResponseDocument,
        ),
        post_document=dict(
            url="",
            name="Create Document",
        ),
        patch_document=dict(
            url="/{uuid_document}",
            name="Update Document",
            responses=OpenApiResponseDocument,
        ),
        delete_document=dict(
            url="/{uuid_document}",
            name="Delete Document and Associated Objects",
            responses=OpenApiResponseDocument,
        ),
    )
    view_children = {"": DocumentSearchView}
    view_router_args = dict(
        tags=[OpenApiTags.documents],
        responses=OpenApiResponseCommon,
    )

    @classmethod
    def get_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
    ) -> AsOutput[DocumentSchema]:
        """Read a document (as `JSON`).

        To render a document, use `GET /documents/{uuid}/rendered`.
        """
        document: Document = access.document(
            uuid_document,
            level=Level.view,
            allow_public=False,
        )
        return mwargs(
            AsOutput[DocumentSchema], data=DocumentSchema.model_validate(document)
        )

    @classmethod
    def get_document_rendered(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
    ) -> FileResponse:
        """Read document content rendered."""
        raise HTTPException(400, detail="Not implemented yet.")

    # TODO: When integration tests are written, all CUD endpoints should
    #       test that the private CUD fields are approprietly set.
    @classmethod
    def post_document(
        cls,
        create: DependsCreate,
        create_data: Annotated[DocumentCreateSchema, Body()],
    ) -> OutputWithEvents[DocumentSchema]:
        """Create a new document.

        To share your document use `POST /grants/documents/{uuid_document}` and
        to assign it to collections use
        `POST /assignments/documents/{uuid_document}`.
        """

        create.create_data = create_data
        data = Data(
            token_user=create.token_user,
            event=None,
            data=ResolvedDocument.empty(),
            children=list(),
        )
        data_create = create.document(data)
        data_create.commit(create.session)
        (document,) = data_create.data.documents

        return mwargs(
            OutputWithEvents[DocumentSchema],
            events=[EventSchema.model_validate(data_create.event)],
            data=DocumentSchema.model_validate(document),
        )

    # TODO: Changing a document from public to private should prune the
    #       assignments from collections where the collection owner does not
    #       level of view. For now, this is not the case and they will be
    #       filtered out of results instead.
    @classmethod
    def patch_document(
        cls,
        uuid_document: args.PathUUIDDocument,
        update: DependsUpdate,
        update_data: Annotated[DocumentUpdateSchema, Body()],
        # rollback: bool = False,
        # uuid_rollback: args.QueryUUIDEditOptional = None,
    ) -> OutputWithEvents[DocumentSchema]:
        """Update document. Updating **content** will result in the current
        document content being moved to an edit.

        To undo updates of the `content` field use **rollback** to revert to
        the most recent edit, or use `uuid_rollback` to specify the exact edit
        uuid to rollback to.

        When changing the public status of a document, bear in mind that it
        will remove the document from any collection where the owner does not
        have a grant on the document.

        To read the edits for a document use
        `GET /documents/{uuid_document}/edits`.
        """

        update.update_data = update_data
        data = update.access.d_document(uuid_document, allow_public=False)
        update.document(data)
        data.commit(update.session)

        return mwargs(
            OutputWithEvents[DocumentSchema],
            events=[EventSchema.model_validate(data.event)],
            data=DocumentSchema.model_validate(*data.data.documents),
        )

    @classmethod
    def delete_document(
        cls,
        uuid_document: args.PathUUIDDocument,
        delete: DependsDelete,
    ) -> AsOutput[DocumentSchema]:
        """Delete a **document** *(and all associated content, such as edits,
        assignments, and collections)*.

        To restore an accidental deletion (within a reasonable timeframe,
        before events and deleted objects are pruned) use
        `POST /events/objects/documents/{uuid_deleted}/restore`.

        To remove a document with no chance of restoration, use **force**. A
        record of the deletion (an `event`) will be kept for some time and
        then eventually pruned.
        """

        data = delete.a_document(uuid_document)
        return mwargs(
            OutputWithEvents[EventSchema],
            data=DocumentSchema.model_validate(data.data.documents[0]),
            events=[EventSchema.model_validate(data.event)],
        )
