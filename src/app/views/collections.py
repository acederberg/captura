from typing import Annotated, List, Tuple

from app import __version__
from app.controllers.base import Data, ResolvedCollection
from app.depends import (DependsCreate, DependsDelete, DependsRead,
                         DependsUpdate)
from app.models import Collection
from app.schemas import (AsOutput, CollectionCreateSchema, CollectionSchema,
                         CollectionUpdateSchema, DocumentMetadataSchema,
                         DocumentSearchSchema, EventSchema, OutputWithEvents,
                         mwargs)
from app.views import args
from app.views.base import BaseView
from fastapi import Body, Depends
from pydantic import TypeAdapter

# --------------------------------------------------------------------------- #
# Depends


def collection(
    uuid_collection: args.PathUUIDCollection,
    read: DependsRead,
) -> Collection:
    collection: Collection = read.access.collection(uuid_collection)
    return collection


DependsCollection = Annotated[Collection, Depends(collection)]


# --------------------------------------------------------------------------- #


class CollectionSearchView(BaseView):

    view_routes = dict(
        get_search_documents="/{uuid_collection}/documents",
        # get_search_collections="",
    )

    @classmethod
    def get_search_documents(
        cls,
        collection: DependsCollection,
        read: DependsRead,
        param: Annotated[DocumentSearchSchema, Depends()],
    ) -> AsOutput[List[DocumentMetadataSchema]]:
        """Return UUIDS for the documents."""

        res: Tuple[Collection, ...] = read.search_collection(collection, param) 
        return mwargs(
            AsOutput[List[DocumentMetadataSchema]],
            data=TypeAdapter(List[DocumentMetadataSchema]).validate_python(
                res
            )
        )

    # @classmethod
    # def get_search_collections(
    #     cls,
    #     collection: DependsCollection,
    #     read: DependsRead,
    #     param: Annotated[CollectionSearchSchema, Depends()],
    # ) -> AsOutput[List[CollectionSchema]]:
    #     res: Tuple[Collection, ...] = read.search_collection(collection, param)
    #     return mwargs(
    #         AsOutput[List[CollectionSchema]],
    #         data=TypeAdapter(List[CollectionSchema]).validate_python(
    #             res
    #         )
    #     )



class CollectionView(BaseView):
    """Routes for collection CRUD and metadata."""

    view_routes = dict(
        get_collection="/{uuid_collection}",
        delete_collection="/{uuid_collection}",
        patch_collection="/{uuid_collection}",
        post_collection="",
    )

    @classmethod
    def get_collection(
        cls,
        collection: DependsCollection
    ) -> AsOutput[CollectionSchema]:
        return mwargs(
            AsOutput[CollectionSchema],
            data=CollectionSchema.model_validate(collection)
        )

    @classmethod
    def delete_collection(
        cls,
        delete: DependsDelete,
        uuid_collection: args.PathUUIDCollection,
    ) -> AsOutput[EventSchema]:

        data: Data[ResolvedCollection] = delete.a_collection(uuid_collection)
        return mwargs(
            AsOutput[EventSchema],
            data=EventSchema.model_validate(data.event)
        )

    @classmethod
    def patch_collection(
        cls,
        update: DependsUpdate,
        uuid_collection: args.PathUUIDCollection,
        updates: Annotated[CollectionUpdateSchema, Body()],
    ) -> OutputWithEvents[CollectionSchema]:
        update.update_data = updates
        data: Data[ResolvedCollection] = update.a_collection(
            uuid_collection,
            resolve_user_token=update.token_user,
        )
        print(data.event.uuid)
        return mwargs(
            OutputWithEvents[CollectionSchema],
            data=CollectionSchema.model_validate(*data.data.collections),
            events=[EventSchema.model_validate(data.event)],
        )

    @classmethod
    def post_collection(
        cls,
        create: DependsCreate,
        create_data:  Annotated[CollectionCreateSchema, Body()],
    ) -> OutputWithEvents[CollectionSchema]:

        # NOTE: User only needs a valid token to create a collection.
        create.create_data = create_data
        create.e_collection
        data = create.e_collection(None)
        collection, = data.data.collections

        return mwargs(
            OutputWithEvents,
            events=[EventSchema.model_validate(data.event)],
            data=CollectionSchema.model_validate(collection)
        )

