# =========================================================================== #
from typing import Annotated

from fastapi import Body, Depends

# --------------------------------------------------------------------------- #
from captura.controllers.base import Data, ResolvedCollection
from captura.depends import DependsCreate, DependsDelete, DependsRead, DependsUpdate
from captura.err import ErrAccessCollection, ErrDetail
from captura.models import Collection
from captura.schemas import (
    AsOutput,
    CollectionCreateSchema,
    CollectionSchema,
    CollectionUpdateSchema,
    EventSchema,
    OutputWithEvents,
    mwargs,
)
from captura.views import args
from captura.views.base import (
    BaseView,
    OpenApiResponseCommon,
    OpenApiResponseUnauthorized,
    OpenApiTags,
)

# Depends


def collection(
    uuid_collection: args.PathUUIDCollection,
    read: DependsRead,
) -> Collection:
    collection: Collection = read.access.collection(uuid_collection, return_data=False)
    return collection


DependsCollection = Annotated[Collection, Depends(collection)]


# --------------------------------------------------------------------------- #

OpenApiResponseCollectionUnauthorized = {
    **OpenApiResponseUnauthorized,
    403: {
        "model": ErrDetail[ErrAccessCollection],
        "description": (
            "Raised when a token user does not own the specified collection "
            "(and in the case of `GET`, only when the collection is not "
            "public and the token user is not the collection owner)."
        ),
    },
}
OpenApiResponseCollection = {
    **OpenApiResponseCommon,
    **OpenApiResponseCollectionUnauthorized,
}


class CollectionSearchView(BaseView):
    view_routes = dict(
        # get_search_documents=dict(
        #     url="/{uuid_collection}/documents",
        #     # name="Search Collection Documents",
        # ),
        # get_search_collections="",
    )
    view_router_args = dict(
        tags=[OpenApiTags.collections],
        responses=OpenApiResponseCollection,
    )

    # @classmethod
    # def get_search_documents(
    #     cls,
    #     collection: DependsCollection,
    #     read: DependsRead,
    #     param: Annotated[DocumentSearchSchema, Depends()],
    # ) -> AsOutput[List[DocumentMetadataSchema]]:
    #     """Return metadata for `documents` (document `JSON` without `content`)
    #     in the `collection` specified by **uuid_collection** matching search
    #     params.
    #     """
    #
    #     res: Tuple[Collection, ...] = read.search_collection(collection, param)
    #     return mwargs(
    #         AsOutput[List[DocumentMetadataSchema]],
    #         data=TypeAdapter(List[DocumentMetadataSchema]).validate_python(res),
    #     )

    # @classmethod
    # def get_search_collections(
    #     cls,
    #     collection: DependsCollection,
    #     read: DependsRead,
    #     param: Annotated[CollectionSearchSchema, Depends()],
    # ) -> AsOutput[List[CollectionSchema]]:
    #     res: Tuple[Collection, ...] = read.search_user(collection, param)
    #     return mwargs(
    #         AsOutput[List[CollectionSchema]],
    #         data=TypeAdapter(List[CollectionSchema]).validate_python(
    #             res
    #         )
    #     )


class CollectionView(BaseView):
    """Routes for collection CRUD and metadata."""

    view_routes = dict(
        get_collection=dict(
            url="/{uuid_collection}",
            name="Read Collection",
            responses=OpenApiResponseCollectionUnauthorized,
        ),
        delete_collection=dict(
            url="/{uuid_collection}",
            name="Delete Collection",
            responses=OpenApiResponseCollectionUnauthorized,
        ),
        patch_collection=dict(
            url="/{uuid_collection}",
            name="Update Collection/Transfer Ownership",
            responses=OpenApiResponseCollectionUnauthorized,
        ),
        post_collection=dict(
            url="",
            name="Create a New Collection",
        ),
    )
    view_children = {"": CollectionSearchView}
    view_router_args = dict(
        tags=[OpenApiTags.collections],
        responses=OpenApiResponseCollection,
    )

    @classmethod
    def get_collection(
        cls, collection: DependsCollection
    ) -> AsOutput[CollectionSchema]:
        """Read a collection.

        To view documents in a collection use
        `GET /collections/{uuid_collection}/documents`.
        """
        return mwargs(
            AsOutput[CollectionSchema], data=CollectionSchema.model_validate(collection)
        )

    @classmethod
    def delete_collection(
        cls,
        delete: DependsDelete,
        uuid_collection: args.PathUUIDCollection,
    ) -> OutputWithEvents[CollectionSchema]:
        """Remove a `collection`.

        This will not remove the `documents` in a `collection` but will remove
        their respective `assignments`."""

        data: Data[ResolvedCollection] = delete.access.d_collection(
            uuid_collection, exclude_deleted=not delete.force
        )
        delete.collection(data)
        serial = CollectionSchema.model_validate(data.data.collections[0])

        data.commit(delete.session)
        return mwargs(
            OutputWithEvents[CollectionSchema],
            data=serial,
            events=[EventSchema.model_validate(data.event)],
        )

    @classmethod
    def patch_collection(
        cls,
        update: DependsUpdate,
        uuid_collection: args.PathUUIDCollection,
        updates: Annotated[CollectionUpdateSchema, Body()],
    ) -> OutputWithEvents[CollectionSchema]:
        """Update a collection/transfer collection ownership.

        When **uuid_user** is specified, the `collection` will be transfered to
        this user. Doing this will not change the `document` permissions such
        that the new owner of the `collection` will be able to access the
        `collection` and in fact the new owner will not see that such
        `documents` exist.
        """
        update.update_data = updates
        data: Data[ResolvedCollection] = update.a_collection(
            uuid_collection,
            resolve_user_token=update.token_user,
        )
        data.commit(update.session)

        return mwargs(
            OutputWithEvents[CollectionSchema],
            data=CollectionSchema.model_validate(*data.data.collections),
            events=[EventSchema.model_validate(data.event)],
        )

    @classmethod
    def post_collection(
        cls,
        create: DependsCreate,
        create_data: Annotated[CollectionCreateSchema, Body()],
    ) -> OutputWithEvents[CollectionSchema]:
        """Create a new collection.

        To add documents to this collection use
        `POST /assignments/collection/{uuid_collection}`.
        """

        # NOTE: User only needs a valid token to create a collection.
        create.create_data = create_data
        data = Data(
            token_user=create.token_user,
            event=None,
            data=ResolvedCollection.empty(),
            children=list(),
        )
        data_create = create.collection(data)
        data_create.commit(create.session)
        (collection,) = data_create.data.collections

        return mwargs(
            OutputWithEvents,
            events=[EventSchema.model_validate(data_create.event)],
            data=CollectionSchema.model_validate(collection),
        )
