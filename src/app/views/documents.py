from http import HTTPMethod
from typing import List, Tuple, overload

from app import __version__
from app.depends import DependsSessionMaker, DependsToken, DependsTokenOptional
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Collection,
    Document,
    Level,
    User,
)
from app.schemas import DocumentMetadataSchema, DocumentSchema, DocumentSearchSchema
from app.views import args
from app.controllers.access import Access
from app.views.base import BaseView
from fastapi import Depends, HTTPException
from sqlalchemy import select


class DocumentView(BaseView):
    view_routes = dict(
        get_document="/{uuid_document}",
        get_documents="",
        post_document="",
        put_document="/{uuid_document}",
        delete_document="/{uuid_document}",
        get_document_edits="/{uuid_document}/edits",
    )

    @classmethod
    def get_document(
        cls,
        makesession: DependsSessionMaker,
        uuid_document: args.PathUUIDDocument,
        token: DependsTokenOptional = None,
    ) -> DocumentSchema:
        with makesession() as session:
            # if not token:
            #     if not document.public:
            #         msg = "User cannot access document."
            #         detail = dict(uuid_document=uuid_document, msg=msg)
            #         raise HTTPException(403, detail=detail)

            access = Access(session, token, method=HTTPMethod.GET)
            document = access.document(uuid_document, level=Level.view)

            return document  # type: ignore

    @classmethod
    def get_documents(
        cls,
        token: DependsTokenOptional,
        makesession: DependsSessionMaker,
        params: DocumentSearchSchema = Depends(),
    ) -> List[DocumentMetadataSchema]:
        with makesession() as session:
            q = Document.q_search(
                token.get("uuid") if token is not None else None,
                params.uuid_document,
                name_like=params.name_like,
                description_like=params.description_like,
                all_=params.all_,
            )
            return list(
                DocumentMetadataSchema.model_validate(item)
                for item in session.execute(q)
            )

    @classmethod
    def get_document_edits(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        uuid: args.PathUUIDUser,
    ): ...

    # TODO: When integration tests are written, all CUD endpoints should
    #       test that the private CUD fields are approprietly set.
    @classmethod
    def post_document(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        documents_raw: List[DocumentSchema],
        uuid_collection: args.QueryUUIDCollection = set(),
        uuid_owner: args.QueryUUIDOwner = set(),
    ):
        uuid = token["uuid"]
        with makesession() as session:
            # Add the documents
            logger.debug("Adding new documents for user `%s`.", uuid)
            documents = {
                document.name: Document(**document.model_dump())
                for document in documents_raw
            }
            session.add_all(documents.values())
            session.commit()

            # Add user ownership for documents.
            logger.debug("Defining ownership of new documents.")
            user_uuids = [uuid, *uuid_owner]
            users: List[User] = list(
                session.execute(
                    select(User).where(User.uuid.in_(user_uuids)),
                ).scalars()
            )

            # NOTE: This must be done directly creating associations because of
            #       the ``_created_by_uuid_user`` and ``_updated_by_uuid_user``
            #       fields.
            assocs_owners = list(
                AssocUserDocument(
                    user_id=user,
                    document_id=document,
                    level="owner",
                )
                for document in documents.values()
                for user in users
            )
            session.add_all(assocs_owners)
            session.commit()

            logger.debug("Adding document to collections `%s`.", uuid_collection)
            collections: List[Collection] = list(
                session.execute(
                    select(Collection).where(
                        Collection.uuid.in_(uuid_collection),
                    )
                ).scalars()
            )
            assocs_collections = list(
                AssocCollectionDocument(
                    id_document=document.id,
                    id_collection=collection.id,
                )
                for document in documents
                for collection in collections
            )
            session.add_all(assocs_collections)
            session.commit()

            return dict(
                documents={dd.uuid: dd.name for dd in documents},
                assoc_collections=list(aa.uuid for aa in assocs_collections),
                assoc_document_owners=user_uuids,
            )

    @classmethod
    def put_document(cls, filter_params):
        # Take current document content and turn it into a document history.
        ...

    @classmethod
    def delete_document(
        cls,
        token: DependsToken,
        sessionmaker: DependsSessionMaker,
        uuid_document: args.PathUUIDDocument,
    ):
        with sessionmaker() as session:
            user, document = cls.verify_access(session, token, uuid_document, Level.own)
            # event_assignments = AssignmentView.delete_assignment(
            #     sessionmaker, token, uuid_collection
            # )
