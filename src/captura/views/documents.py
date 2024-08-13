# =========================================================================== #
from typing import Annotated

from fastapi import Body

# --------------------------------------------------------------------------- #
from captura.controllers.base import Data, ResolvedDocument
from captura.depends import DependsAccess, DependsCreate, DependsDelete, DependsUpdate
from captura.models import Document, Level
from captura.schemas import (
    AsOutput,
    DocumentCreateSchema,
    DocumentSchema,
    DocumentUpdateSchema,
    EventSchema,
    OutputWithEvents,
    mwargs,
)
from captura.views import args
from captura.views.base import (
    BaseView,
    OpenApiResponseCommon,
    OpenApiResponseDocumentForbidden,
    OpenApiTags,
)

OpenApiResponseDocument = {
    **OpenApiResponseCommon,
    **OpenApiResponseDocumentForbidden,
}


class DocumentView(BaseView):
    view_routes = dict(
        get_document=dict(
            url="/{uuid_document}",
            name="Get Document JSON",
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
            allow_public=True,
            return_data=False,
        )
        return mwargs(
            AsOutput[DocumentSchema], data=DocumentSchema.model_validate(document)
        )

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

        # TODO: Make this work as a single transaction.
        create.create_data = create_data
        data = Data[ResolvedDocument](
            token_user=create.token_user,
            event=None,
            data=ResolvedDocument.empty(token_user_grants=dict()),
            children=list(),
        )
        data_create = create.document(data)
        data_create.commit(create.session)
        (document,) = data_create.data.documents

        grant, *_ = data_create.data.token_user_grants.values()
        grant.id_document = document.id
        create.session.add(grant)
        create.session.commit()

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
    ) -> OutputWithEvents[DocumentSchema]:
        """Update document metadata."""

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
    ) -> OutputWithEvents[DocumentSchema]:
        """Delete a **document** *(and all associated content, such as edits,
        assignments, and collections)*.

        To restore an accidental deletion (within a reasonable timeframe,
        before events and deleted objects are pruned) use
        `POST /events/objects/documents/{uuid_deleted}/restore`.

        To remove a document with no chance of restoration, use **force**. A
        record of the deletion (an `event`) will be kept for some time and
        then eventually pruned.
        """

        data = delete.a_document(uuid_document, exclude_deleted=not delete.force)
        data.commit(delete.session)
        return mwargs(
            OutputWithEvents[DocumentSchema],
            data=DocumentSchema.model_validate(data.data.documents[0]),
            events=[EventSchema.model_validate(data.event)],
        )
