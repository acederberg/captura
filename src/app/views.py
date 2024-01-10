"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.
"""
import logging
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    Type,
    TypeAlias,
)

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query
from fastapi.params import Param
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from sqlalchemy import delete, func, label, literal_column, select
from sqlalchemy.orm import Session, sessionmaker

from app import __version__, util
from app.depends import (
    DependsAuth,
    DependsConfig,
    DependsFilter,
    DependsSessionMaker,
    DependsToken,
    DependsUUID,
)
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Collection,
    Document,
    Edit,
    Event,
    EventKind,
    Level,
    ObjectKind,
    User,
)
from app.schemas import (
    UUID,
    CollectionMetadataSchema,
    CollectionSchema,
    DocumentMetadataSchema,
    DocumentSchema,
    EditMetadataSchema,
    EditSchema,
    EventSchema,
    GrantPostSchema,
    GrantSchema,
    PostUserSchema,
    UserSchema,
    UserUpdateSchema,
)

logger = util.get_logger(__name__)
QueryUUIDCollection: TypeAlias = Annotated[
    List[str], Query(min_length=4, max_length=16)
]
QueryUUIDOwner: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocument: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocumentOptional: TypeAlias = Annotated[Optional[Set[str]], Query()]
QueryUUIDUser: TypeAlias = Annotated[Set[str], Query(min_length=0)]
QueryUUIDUserOptional: TypeAlias = Annotated[None | Set[str], Query(min_length=0)]
QueryLevel: TypeAlias = Annotated[Literal["view", "modify", "own"], Query()]
PathUUIDUser: TypeAlias = Annotated[str, Path()]
PathUUIDCollection: TypeAlias = Annotated[str, Path()]
PathUUIDDocument: TypeAlias = Annotated[str, Path()]


# =========================================================================== #
# Base Views.


class ViewMixins:
    """

    :attr view_children: Dictionary of instances to instances.
    :attr view_router: The router built by :class:`ViewMeta`.
    :attr view: Mapping from router function names to router routes.
    """

    # view_children: ClassVar[Dict[str, Type]] = dict()
    view_children: ClassVar[Dict[str, "ViewMeta"]] = dict()
    view_router: ClassVar[APIRouter]
    view_router_args: ClassVar[Dict[str, Any]] = dict()
    view_routes: ClassVar[Dict[str, str]] = dict()


class ViewMeta(type):
    """Metaclass to handle routing.

    It will build a router under `view`.
    """

    @classmethod
    def add_route(cls, T, name_fn: str, route: APIRoute):
        name = T.__name__
        if "_" not in name_fn:
            logger.debug(
                "Ignoring `%s -> %s` of `%s.view_routes`.", name_fn, route, name
            )
            return

        logger.debug("Adding `%s` to `%s` router at `%s`.", name_fn, name, route)
        http_meth, _ = name_fn.split("_", 1)
        match http_meth:
            case "get" | "post" | "delete" | "patch" | "put":
                fn = getattr(T, name_fn, None)
                if fn is None:
                    msg = f"No such method `{name_fn}` of `{name}`."
                    raise ValueError(msg)
                getattr(T.view_router, http_meth)(route)(fn)  # type: ignore
            case _:
                logger.debug("Skipping `%s.%s`.", name, name_fn)

    def __new__(cls, name, bases, namespace):
        T = super().__new__(cls, name, bases, namespace)
        logger.debug("Validating `%s` router.", name)

        # Validate `view_children`.
        if not hasattr(T, "view_children"):
            raise ValueError(f"`{name}` must define `view_children`.")
        elif not isinstance(T.view_children, dict):  # type: ignore
            raise ValueError(f"`{name}.view_children` must be a `dict`.")

        # Validate `view`.
        if not hasattr(T, "view_routes"):
            raise ValueError(f"`{name}` must define `view`.")
        elif not isinstance(T.view_routes, dict):  # type: ignore
            raise ValueError(f"`{name}.view` must be a dict.")

        # Validate `view_router_args`.
        if not hasattr(T, "view_router_args"):
            raise ValueError(f"`{name}` must define `view_router_args`.")
        elif not isinstance(T.view_router_args, dict):  # type: ignore
            raise ValueError(f"`{name}.view_router_args` must be a `dict`.")

        if name != "BaseView":
            # Create router.
            logger.debug("Creating router for `%s`.", name)
            T.view_router = (  # type: ignore
                T.view_router  # type: ignore
                if hasattr(T, "view_router")
                else APIRouter(**T.view_router_args)  # type: ignore
            )
            for name_fn, route in T.view_routes.items():  # type: ignore
                cls.add_route(T, name_fn, route)

            for child_prefix, child in T.view_children.items():  # type: ignore
                logger.debug(
                    "Adding child router `%s` for `%s`.",
                    child_prefix,
                    name,
                )
                T.view_router.include_router(  # type: ignore
                    child.view_router,
                    prefix=child_prefix,
                )

        return T


class BaseView(ViewMixins, metaclass=ViewMeta):
    ...


# =========================================================================== #
# Views


class DocumentView(BaseView):
    view_routes = dict(
        get_document="/{uuid}",
        get_documents="",
        post_document="",
        put_document="",
        delete_document="",
        get_document_edits="/edits",
    )

    @classmethod
    def get_document(
        cls, makesession: DependsSessionMaker, uuid: PathUUIDUser
    ) -> DocumentSchema:
        with makesession() as session:
            document: Document | None = session.execute(
                select(Document).where(Document.uuid == uuid)
            ).scalar()
            if document is None:
                raise HTTPException(204)
            return document  # type: ignore

    @classmethod
    def get_documents(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        filter: DependsFilter,
    ) -> Dict[str, DocumentMetadataSchema]:
        with makesession() as session:
            results = {
                item.name: item
                for item in session.execute(
                    select(Document).limit(filter.limit)
                ).scalars()
            }
            return results  # type: ignore

    @classmethod
    def get_document_edits(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        uuid: PathUUIDUser,
    ):
        ...

    # TODO: When integration tests are written, all CUD endpoints should
    #       test that the private CUD fields are approprietly set.
    @classmethod
    def post_document(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        documents_raw: List[DocumentSchema],
        uuid_collection: QueryUUIDCollection = list(),
        uuid_owner: QueryUUIDOwner = list(),
    ):
        uuid = token["uuid"]
        with makesession() as session:
            # Add the documents
            logger.debug("Adding new documents for user `%s`.", uuid)
            Document._updated_by_user_uuid
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
    def delete_document(cls):
        ...


class CollectionView(BaseView):
    """Routes for collection CRUD and metadata."""

    view_routes = dict(
        get_collection="/{uuid}",
        get_collection_documents="/{uuid}/documents",
        delete_collection="/{uuid}",
        update_collection="/{uuid}",
        post_collection="/{uuid}",
    )

    @classmethod
    def get_collection(cls, filter_params):
        ...

    @classmethod
    def get_collection_documents(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDCollection,
    ) -> List[str]:
        """Return UUIDS for the documents."""

        with sessionmaker() as session:
            collection = Collection.if_exists(session, uuid)
            user = User.if_exists(session, token["uuid"]).check_can_access_collection(
                collection
            )
            session.execute(
                select(Document.uuid)
                .select_from(Document)
                .join(AssocCollectionDocument)
                .join(Collection)
                .where(Collection.uuid == uuid)
            ).scalars()

    @classmethod
    def delete_collection(cls, filter_params):
        ...

    @classmethod
    def update_collection(cls, filter_params):
        ...

    @classmethod
    def post_collection(cls, filter_params):
        ...


class GrantView(BaseView):
    # NOTE: Updates should not be supported. It makes more sense to just delete
    #       the permissions and create new ones.
    view_routes = dict(
        delete_grants="/documents/{uuid_document}",
        post_grants="/documents/{uuid_document}",
        get_grants_document="/documents/{uuid_document}",
        get_grants_user="/users/{uuid_user}",
    )

    # ----------------------------------------------------------------------- #
    # Sharing.

    @classmethod
    def delete_grants(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_user: QueryUUIDUser,
    ) -> EventSchema:
        """Revoke access to the specified users on the specified document."""

        # NOTE: Permissions should be hard deleted unlike first class rows.
        #       Make sure that the revoker owns the specified document.
        uuid_revoker = token["uuid"]
        with makesession() as session:
            logger.debug("Verifying document ownership.")
            document: Document = Document.if_exists(session, uuid_document)
            revoker = User.if_exists(session, uuid_revoker, 403)
            revoker.check_can_access_document(document, Level.own)

            # NOTE: Since owners cannot reject the ownership of other owners.
            logger.debug("Verifying revokee permissions.")
            q_select_grants = document.q_select_grants(uuid_user)
            uuid_owners: List[str] = list(
                session.execute(
                    select(literal_column("uuid_user"))
                    .select_from(q_select_grants)  # type: ignore
                    .where(literal_column("level") == Level.own)
                ).scalars()
            )
            if len(uuid_owners):
                detail = dict(
                    msg="Owner cannot reject owners permission.",
                    uuid_user_revoker=uuid_revoker,
                    uuid_user_revokees=uuid_owners,
                    uuid_documents=uuid_document,
                )
                raise HTTPException(403, detail=detail)

            # NOTE: Base event indicates the document, secondary event
            #       indicates the users for which permissions were revoked.
            #       Tertiary event indicates information about the association
            #       object.
            grants = list(session.execute(q_select_grants))
            event = Event(
                **(
                    common := dict(
                        api_origin="DELETE /grants/documents/<uuid>",
                        uuid_user=uuid_revoker,
                        kind=EventKind.grant,
                    )
                ),
                uuid_obj=uuid_document,
                kind_obj=ObjectKind.document,
                detail="Grants revoked.",
            )
            event.children = list(
                Event(
                    **common,
                    kind_obj=ObjectKind.user,
                    uuid_obj=grant.uuid_user,
                    detail=f"Grant `{grant.level}` revoked.",
                    children=[
                        Event(
                            **common,
                            kind_obj=ObjectKind.assoc_user_document,
                            uuid_obj=grant.uuid,
                            detail=f"Grant `{grant.level}` revoked.",
                        )
                    ],
                )
                for grant in grants
            )
            session.add(event)
            session.execute(
                delete(AssocUserDocument).where(document.q_conds_grants(uuid_user))
            )
            session.commit()

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def get_grants_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: PathUUIDUser,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> List[GrantSchema]:
        """Check that a user has access to the specified document.

        This function will likely be called in document CUD. But can be used
        to retrieve truthiness of an access level.
        """

        with makesession() as session:
            user = User.if_exists(session, token["uuid"])
            if user.uuid != uuid_user:
                detail = dict(msg="Users can only read their own grants.")
                raise HTTPException(403, detail=detail)
            assoc = session.execute(user.q_select_grants(uuid_document))

            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in assoc
            ]

    @classmethod
    def get_grants_document(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_user: QueryUUIDUserOptional = None,
    ) -> List[GrantSchema]:
        """List document grants.

        This could be useful somewhere in the UI. For instance, for owners
        granting permissions.
        """

        with makesession() as session:
            # Verify that user has access
            document = Document.if_exists(session, uuid_document)

            user = User.if_exists(session, token["uuid"], 403)
            user.check_can_access_document(document, Level.own)

            results = session.execute(document.q_select_grants(uuid_user))
            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in results
            ]

    @classmethod
    def post_grants(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        grants: List[GrantPostSchema],
    ) -> EventSchema:
        """This endpoint can be used to share a document with another user.

        To revoke document access, use ``DELETE`` version of this endpoint. To
        undo grants from this endpoint, just send DELETE request to the same
        url. To this end, this endpoint is indempotent - posting existing
        grants will change nothing in the database, even if you change the
        level specified in the ``POST`` request.

        To see if a user had grants on a particluar document or not, use
        ``GET /grants/documents/<uuid>`` - To see all of a users grants use
        ``GET /grants/users/<uuid>``.


        :param uuid: Target uuid. The user to grant permissions to.
        :param level: Level to grant. One of "view", "modify", or
            "owner".
        :param uuid_document: The uuids of the documents to grant these
            permissions on.
        """

        with makesession() as session:
            logger.debug("Verifying granter permissions.")
            document: Document = Document.if_exists(session, uuid_document, 404)
            granter: User = User.if_exists(session, token["uuid"], 403)
            granter.check_can_access_document(document, Level.own)

            logger.debug("Verifying that grantees exist.")
            uuids_users = set(gg.uuid_user for gg in grants)
            ids_uuids = {
                k: v
                for k, v in session.execute(
                    select(User.uuid, User.id).where(User.uuid.in_(uuids_users))
                )
            }
            if len(bad := uuids_users - set(ids_uuids)):
                detail = dict(
                    msg="Cannot grant to users that do not exist.",
                    uuid_user=bad,
                )
                raise HTTPException(400, detail=detail)

            # NOTE: Pick out grants that already exist. These grants will not
            #       be created and this will evident from the response.
            logger.debug("Finding existing grants.")
            uuids_existing = set(
                session.execute(
                    select(literal_column("uuid_user")).select_from(
                        document.q_select_grants(uuids_users)  # type: ignore
                    )
                ).scalars()
            )

            logger.debug("Creating associations for grants.")
            assocs = {
                gg.uuid_user: AssocUserDocument(
                    id_user=ids_uuids[gg.uuid_user],
                    id_document=document.id,
                    level=gg.level,
                )
                for gg in grants
                if gg.uuid_user not in uuids_existing
            }
            session.add_all(assocs.values())
            session.commit()

            # NOTE: Events returned by this endpoint should look like those
            #       returned from the corresponding DELETE endpoint.
            logger.debug("Creating events for grant.")
            common = dict(
                kind=EventKind.grant,
                uuid_user=granter.uuid,
                detail="Grants issued.",
                api_origin="POST /grants/documents/<uuid>",
                api_version=__version__,
            )
            event = Event(
                **common,
                uuid_obj=uuid_document,
                kind_obj=ObjectKind.document,
                children=[
                    Event(
                        **common,
                        uuid_obj=uuid_user,
                        kind_obj=ObjectKind.user,
                        children=[
                            Event(
                                **common,
                                uuid_obj=assoc.uuid,
                                kind_obj=ObjectKind.assoc_user_document,
                            )
                        ],
                    )
                    for uuid_user, assoc in assocs.items()
                ],
            )
            session.add(event)
            session.commit()

            return JSONResponse(
                EventSchema.model_validate(event).model_dump(),
                201,
            )  # type: ignore


class UserView(BaseView):
    """Routes for user data and metadata.

    This will be put on ``/users``.
    """

    view_routes = dict(
        get_users="",
        get_user="/{uuid}",
        patch_user="/{uuid}",
        delete_user="/{uuid}",
        post_user="",
        get_user_documents="/{uuid}/documents",
        get_user_edits="/{uuid}/edits",
        get_user_collections="/{uuid}/collections",
    )

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    @classmethod
    def get_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
    ) -> UserSchema:
        """Get user metadata.

        For instance, this should be used to make a profile page.
        """

        with makesession() as session:
            user = User.if_exists(session, uuid, 404)
            return user  # type: ignore

    # NOTE: The token depends is included since API billing will depend on
    #       users having a valid token. Later I would like to make it such that
    #       it will also accept requests without tokens from particular
    #       origins, for instance a site where articles may be publicly viewed.
    @classmethod
    def get_users(
        cls,
        makesession: DependsSessionMaker,
        filter: DependsFilter,
        token: DependsToken,
        # collaborators: bool = False,
    ) -> List[UserSchema]:
        """Get user collaborators or just list some users.

        Once authentication is integrated, getting collaborators will be
        possible. Collaborators will only be possible when the caller has an
        account, otherwise some random users should be returned.
        """
        with makesession() as session:
            result: List[User] = list(
                session.execute(select(User).limit(filter.limit)).scalars()
            )
            if not len(result):
                raise HTTPException(204)
            return result  # type: ignore

    # NOTE: This should not be decorated but should be used in the individual
    #       getters with clearer (not a union) type hints (the ``child``
    #       parameter will not appear in actual endpoints.).
    @classmethod
    def select_user_child(
        cls,
        child: Literal["collections", "edits", "documents"],
        makesession: sessionmaker[Session],
        uuid: PathUUIDUser,
    ) -> Any:
        """Get user ``collections`` and ``edits`` data without content.

        :param child: Child to get metadata for. Must be one of ``collections``
            or ``edits``. For ``documents`` use the ``/document`` endpoints.
        :param filter_params: Use these parameters to filter out which children
            to display.
        """

        with makesession() as session:
            user: User = User.if_exists(session, uuid)
            children: List[Collection] | List[Edit] | List[Document]
            children = getattr(user, child)
            if not len(children):
                JSONResponse([], 204)

            return children  # type: ignore

    @classmethod
    def get_user_documents(
        cls, makesession: DependsSessionMaker, uuid: PathUUIDUser
    ) -> Dict[str, DocumentMetadataSchema]:
        return cls.select_user_child(
            "documents",
            makesession,
            uuid,
        )

    @classmethod
    def get_user_collections(
        cls, makesession: DependsSessionMaker, uuid: PathUUIDUser
    ) -> Dict[str, CollectionMetadataSchema]:
        return cls.select_user_child(
            "collections",
            makesession,
            uuid,
        )

    @classmethod
    def get_user_edits(
        cls, makesession: DependsSessionMaker, uuid: PathUUIDUser
    ) -> List[EditMetadataSchema]:
        return cls.select_user_child(
            "edits",
            makesession,
            uuid,
        )

    # ----------------------------------------------------------------------- #
    # CRUD without R

    @classmethod
    def patch_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        updates: UserUpdateSchema = Depends(),
    ) -> EventSchema:
        """Update a user.

        Only the user themself should be able to update this.
        """
        if not uuid == token["uuid"]:
            raise HTTPException(403, detail="Users can only modify their own account.")

        with makesession() as session:
            user = User.if_exists(session, uuid)

            # NOTE: Don't forget to include the metadata.
            updates_dict = updates.model_dump()
            event_common = dict(
                uuid_user=uuid,
                uuid_obj=uuid,
                kind=EventKind.update,
                kind_obj=ObjectKind.user,
                api_origin="PATCH /users/<uuid>",
            )
            event = Event(**event_common, detail="Updated user.")
            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(user, key, value)
                event.children.append(
                    Event(**event_common, detail=f"Updated user {key}.")
                )
            session.add(event)
            session.add(user)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def delete_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        restore: bool = False,
    ) -> EventSchema:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """
        if not uuid == token["uuid"]:
            raise HTTPException(
                403, detail="Users can only delete/restore their own account."
            )
        with makesession() as session:
            user = User.if_exists(session, uuid)

            api_origin = "DELETE /users/<uuid>"
            msg = "deleted" if not restore else "restored"
            event = Event(
                uuid_user=uuid,
                uuid_obj=uuid,
                kind=EventKind.delete,
                kind_obj=ObjectKind.user,
                detail=f"User {msg}.",
                api_origin=api_origin,
            )

            # Get exclusive_documents.
            exclusive_documents = list(
                session.execute(user.q_select_documents_exclusive())
            )
            for dd in exclusive_documents:
                event.children.append(
                    Event(
                        uuid_user=uuid,
                        uuid_obj=dd.uuid,
                        kind_obj=ObjectKind.document,
                        kind=EventKind.delete,
                        detail=f"Document {msg}.",
                        api_origin=api_origin,
                    )
                )
                session.add(event)

                dd.deleted = not restore
                session.add(dd)

            user.deleted = not restore
            session.add(user)
            session.add(event)
            session.commit()

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def post_user(
        cls,
        makesession: DependsSessionMaker,
        data: PostUserSchema,
    ) -> EventSchema:
        """Create a user.

        For now sharing of collections or documents can be done through
        calling `POST /grant/users/<uuid>/documents/<uuid_document>` endpoints.
        """
        api_origin = "POST /users"
        with makesession() as session:
            session.add(
                user := User(**data.model_dump(exclude={"collections", "documents"}))
            )
            session.commit()
            session.refresh(user)

            events_common = dict(
                uuid_user=user.uuid,
                api_origin=api_origin,
                kind=EventKind.create,
            )
            session.add(
                event := Event(
                    **events_common,
                    uuid_obj=user.uuid,
                    kind_obj=ObjectKind.user,
                    detail="User created.",
                )
            )
            session.commit()

            if data.collections:
                session.add_all(
                    collections := [
                        Collection(**cc.model_dump(), id_user=user.id)
                        for cc in data.collections
                    ]
                )
                session.commit()
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=cc.uuid,
                            kind_obj=ObjectKind.collection,
                            detail="Collection created.",
                        )
                        for cc in collections
                    ]
                )
                session.commit()
            if data.documents:
                session.add_all(
                    documents := [Document(**dd.model_dump()) for dd in data.documents]
                )
                session.commit()
                user.documents = {dd.name: dd for dd in documents}
                session.add(user)
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=dd.uuid,
                            kind_obj=ObjectKind.document,
                            detail="Document created.",
                        )
                        for dd in documents
                    ]
                )
                session.commit()

            session.refresh(event)
            return JSONResponse(  # type: ignore
                EventSchema.model_validate(event).model_dump(),
                status_code=201,
            )


class AuthView(BaseView):
    """This is where routes to handle login and getting tokens will be."""

    view_routes = {"post_token": "/token", "get_login": "/login"}

    @classmethod
    def post_token(
        cls, config: DependsConfig, auth: DependsAuth, payload: Dict[str, Any]
    ) -> str:
        """Use this to create a new token.

        This endpoint only works when authentication is in pytest mode, and
        will not use auth0 mode. NEVER run this application in production while
        using tokens in endpoint mode, it will allow undesired access to user
        information (because anybody could imitate any user by minting a token
        with that particular users UUID.
        """
        logger.warning("Minting token...")
        if config.auth0.use:
            raise HTTPException(
                409,
                detail="Token minting is not available in auth0 mode.",
            )
        return auth.encode(payload)

    @classmethod
    def get_login(cls, config: DependsConfig):
        if not config.auth0.use:
            raise HTTPException(
                409,
                detail="Login is not available in pytest mode.",
            )


class AppView(BaseView):
    view_router = FastAPI()  # type: ignore
    view_routes = {"get_index": "/"}
    view_children = {
        "/grants": GrantView,
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthView,
    }

    @classmethod
    def get_index(cls, uuid: int, makesession: DependsSessionMaker) -> None:
        ...
