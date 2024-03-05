from http import HTTPMethod
from typing import Annotated, List, Tuple, overload

from app import __version__
from app.controllers.access import Access
from app.controllers.base import Data, ResolvedDocument
from app.depends import (DependsAccess, DependsCreate, DependsDelete,
                         DependsRead, DependsSessionMaker, DependsToken,
                         DependsTokenOptional, DependsUpdate)
from app.models import (AssocCollectionDocument, AssocUserDocument, Collection,
                        Document, Level, User)
from app.schemas import (AsOutput, DocumentCreateSchema,
                         DocumentMetadataSchema, DocumentSchema,
                         DocumentSearchSchema, DocumentUpdateSchema,
                         EditSchema, EditSearchSchema, EventSchema,
                         OutputWithEvents, TimespanLimitParams, mwargs)
from app.views import args
from app.views.base import BaseView
from fastapi import Body, Depends, HTTPException
from pydantic import TypeAdapter
from sqlalchemy import select


class DocumentSearchView(BaseView):
    view_routes = dict(
        get_recent_documents="",
        get_recent_document_edits="/{uuid_document}/edits",
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
        document, = data.data.documents

        q = document.q_select_edits(
            before=param.before_timestamp,
            after=param.after_timestamp,
            limit=param.limit,
        )
        res = read.session.execute(q)
        edits = tuple(res.scalars())
        return mwargs(
            AsOutput[EditSchema],
            data=TypeAdapter(List[EditSchema]).validate_python(edits)
        )


class DocumentView(BaseView):
    view_routes = dict(
        get_document="/{uuid_document}",
        post_document="",
        patch_document="/{uuid_document}",
        delete_document="/{uuid_document}",
    )
    view_children = {"/recent": DocumentSearchView}

    @classmethod
    def get_document(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
    ) -> AsOutput[DocumentSchema]:
        document: Document = access.document(uuid_document, level=Level.view)
        return mwargs(
            AsOutput[DocumentSchema],
            data=DocumentSchema.model_validate(document)
        )

    # TODO: When integration tests are written, all CUD endpoints should
    #       test that the private CUD fields are approprietly set.
    @classmethod
    def post_document(
        cls,
        create: DependsCreate,
        create_data: Annotated[DocumentCreateSchema, Body()],
    ) -> OutputWithEvents[DocumentSchema]:

        create.create_data = create_data
        data = create.e_document(None)

        return mwargs(
            OutputWithEvents[DocumentSchema],
            events=[EventSchema.model_validate(data.event)],
            data=DocumentSchema.model_validate(data.data.documents)
        )

    @classmethod
    def patch_document(
        cls, 
        uuid_document: args.PathUUIDDocument,
        update: DependsUpdate,
        update_data: Annotated[DocumentUpdateSchema, Body()],
    ) -> OutputWithEvents[DocumentSchema]:

        update.update_data = update_data
        data = update.a_document(uuid_document)

        return mwargs(
            OutputWithEvents[DocumentSchema],
            events=[EventSchema.model_validate(data.event)],
            data=DocumentSchema.model_validate(*data.data.documents)
        )

    @classmethod
    def delete_document(
        cls,
        uuid_document: args.PathUUIDDocument,
        delete: DependsDelete,
    ) -> AsOutput[DocumentSchema]:

        data = delete.a_document(uuid_document)
        return mwargs(
            OutputWithEvents[EventSchema],
            data=DocumentSchema.model_validate(data.data.documents[0]),
            events=[EventSchema.model_validate(data.event)],
        )
