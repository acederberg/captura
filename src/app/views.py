"""Api routers and functions. 

This includes a metaclass so that undecorated functions may be tested.
"""
import logging
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Set, Type, TypeAlias

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query
from fastapi.params import Param
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy import func, label, literal_column, select
from sqlalchemy.orm import Session, sessionmaker

from app import util
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
    UserSchema,
    UserUpdateSchema,
)

logger = util.get_logger(__name__)
QueryUUIDCollection: TypeAlias = Annotated[
    List[str], Query(min_length=4, max_length=16)
]
QueryUUIDOwner: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocument: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDUser: TypeAlias = Annotated[Set[str], Query(min_length=0)]
QueryLevel: TypeAlias = Annotated[Literal["view", "modify", "own"], Query()]
PathUUIDUser: TypeAlias = Annotated[str, Path()]
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
                session.execute(select(User).where(User.uuid.in_(user_uuids))).scalars()
            )

            # NOTE: This must be done directly creating associations because of
            #       the ``_created_by_uuid_user`` and ``_updated_by_uuid_user``
            #       fields.
            assocs_owners = list(
                AssocUserDocument(user_id=user, document_id=document, level="owner")
                for document in documents.values()
                for user in users
            )
            session.add_all(assocs_owners)
            session.commit()

            logger.debug("Adding document to collections `%s`.", uuid_collection)
            collections: List[Collection] = list(
                session.execute(
                    select(Collection).where(Collection.uuid.in_(uuid_collection))
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
        get_collection="/",
        get_collection_documents="/documents",
        delete_collection="/",
        update_collection="/",
        post_collection="/",
    )

    @classmethod
    def get_collection(cls, filter_params):
        ...

    @classmethod
    def get_collection_documents(cls):
        ...

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
        post_user_document_access="/users/{uuid_user}",
        get_document_user_access="/documents/{uuid_document}",
        get_user_document_access="/users/{uuid_user}/documents/{uuid_document}",
        delete_document_access="/users/{uuid_user}/documents/{uuid_document}",
        # update_document_access="/{uuid}",
    )

    # ----------------------------------------------------------------------- #
    # Sharing.

    @classmethod
    def delete_document_access(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: PathUUIDUser,
        uuid_document: PathUUIDDocument,
    ):
        """Revoke access to the specified user on the specified document."""

        # NOTE: Permissions should be hard deleted unlike first class rows.
        with makesession() as session:
            q_assoc = select(AssocUserDocument).where(
                AssocUserDocument.id_user
                == select(User.id).where(User.uuid == uuid_user),
                AssocUserDocument.id_document
                == select(Document.id).where(Document.uuid == uuid_document),
            )
            assoc = session.execute(q_assoc).scalar()
            if assoc is None:
                _ = "User had no permissions for the specified document"
                _ = dict(msg=msg, uuid_document=uuid_document, uuid_user=uuid_user)
                raise HTTPException(404, detail=_)

            session.delete(assoc)

            event = Event(
                kind=EventKind.grant,
                uuid_user=uuid_user,
                kind_obj=ObjectKind.assoc_user_document,
                uuid_obj=uuid_document,
                detail="Deleted grant.",
            )
            session.add(event)
            session.commit()

    @classmethod
    def get_user_document_access(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: PathUUIDUser,
        uuid_document: PathUUIDDocument,
        level: QueryLevel,
    ) -> bool:
        """Check that a user has access to the specified document.

        This function will likely be called in document CUD. But can be used
        to retrieve truthiness of an access level.
        """

        with makesession() as session:
            assoc = session.execute(
                select(AssocUserDocument).where(
                    AssocUserDocument.id_user == select(User.id),
                    User.uuid == token["uuid"],
                )
            ).scalar()

            if assoc is None:
                raise HTTPException(
                    404,
                    detail=dict(
                        msg="Permission does not exist.",
                        uuid_user=uuid_user,
                        uuid_document=uuid_document,
                    ),
                )
            return assoc.level.value >= Level[level].value

    @classmethod
    def get_document_user_access(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_user: QueryUUIDUser,
    ) -> Dict[str, Level]:
        """List document grants.

        This could be useful somewhere in the UI. For instance, for owners
        granting permissions.
        """
        uuid = token["uuid"]
        with makesession() as session:
            user = session.execute(select(User).where(User.uuid == uuid)).scalar()
            if user is None:
                raise HTTPException(418)

            document = session.execute(
                select(Document).where(Document.uuid == uuid_document)
            ).scalar()
            if document is None:
                raise HTTPException(404)

            user_levels = document.get_user_levels(uuid_user)
            if user.uuid not in user_levels or user_levels[user.uuid] != Level.own:
                _ = "Insufficient permission to view document permissions."
                _ = dict(msg=_, uuid_user=uuid, uuid_document=document.uuid)
                raise HTTPException(403, _)

            return user_levels

    @classmethod
    def post_user_document_access(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: PathUUIDUser,
        level: QueryLevel,
        uuid_document: QueryUUIDDocument,
    ) -> List[str]:
        """This endpoint can be used to share a document with another user.

        To revoke document access, use the ``PATCH`` or ``DELETE`` versions of
        this endpoint. To see if you can access document(s) or not, use
        ``GET``.

        :param uuid: Target uuid. The user to grant permissions to.
        :param level: Level to grant. One of "view", "modify", or
            "owner".
        :param uuid_document: The uuids of the documents to grant these
            permissions on.
        """

        uuid_granter = token["uuid"]
        with makesession() as session:
            logger.debug("Verifying granter permissions.")
            granter = session.execute(
                select(User).where(User.uuid == uuid_granter)
            ).scalar()
            if granter is None:
                raise HTTPException(418)
            elif bad := granter.document_uuids(Level[level], uuid_document):
                raise HTTPException(
                    403,
                    detail=dict(
                        msg="Cannot perform grants on some objects.", uuids=bad
                    ),
                )

            # Get grantee.
            grantee: User | None = session.execute(
                select(User).where(User.uuid == uuid_user)
            ).scalar()
            if grantee is None:
                raise HTTPException(404)

            logger.debug("Creating associations for grant.")
            id_documents: Set[int] = set(
                session.execute(
                    select(Document.id).where(Document.uuid.in_(uuid_document))
                ).scalars()
            )
            assocs = [
                AssocUserDocument(
                    level=level,
                    id_user=grantee.id,
                    id_document=id_,
                )
                for id_ in id_documents
            ]
            session.add_all(assocs)
            session.commit()

            logger.debug("Creating events for grant.")
            event = Event(
                kind=EventKind.grant,
                uuid_user=uuid_granter,
                uuid_obj=uuid_user,
                kind_obj=ObjectKind.user,
                detail="Grant created.",
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            for assoc in assocs:
                session.refresh(assoc)
                session.add(
                    Event(
                        uuid_event_parent=event.uuid,
                        uuid_user=grantee.id,
                        uuid_obj=assoc.uuid,
                        kind=event.kind,
                        kind_obj=ObjectKind.assoc_user_document,
                        detail="grant_created",
                    )
                )
            session.commit()

        return [assoc.uuid for assoc in assocs]


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

        if uuid is None:
            uuid = token["uuid"]
        with makesession() as session:
            result: None | User = session.execute(
                select(User).where(User.uuid == uuid)
            ).scalar()
            if result is None:
                raise HTTPException(204)
            return result  # type: ignore

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
            user: None | User = session.execute(
                select(User).where(User.uuid == uuid)
            ).scalar()
            if user is None:
                raise HTTPException(404)
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
    ):
        """Update a user.

        Only the user themself should be able to update this.
        """
        if not uuid == token["uuid"]:
            raise HTTPException(403, detail="Users can only modify their own account.")

        with makesession() as session:
            user: User | None = session.execute(
                select(User).where(User.uuid == uuid)
            ).scalar()
            if user is None:
                raise HTTPException(418, detail="User not found.")

            # NOTE: Don't forget to include the metadata.
            updates_dict = updates.model_dump()
            # updates_dict.update(updated_info)
            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(user, key, value)
            session.add(user)
            session.commit()

    @classmethod
    def delete_user(
        cls,
        makesession: DependsSessionMaker,
        uuid: PathUUIDUser,
    ) -> UUID:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """
        with makesession() as session:
            _ = select(User).where(User.uuid == uuid)
            user: User | None = session.execute(_).scalar()
            if user is None:
                raise HTTPException(418, detail="User not found.")

            # Get all assocs where the user is the exclusive owner.
            # q_assocs = select(AssocUserDocument).where(
            #             AssocUserDocument.id_user == user.id,
            #             AssocUserDocument.level == "owner",
            #         )

            # TODO: These queries should be factored out so they can be tested.
            # q_counts = select( literal_column("id_document")).select_from(
            #     select(AssocUserDocument.id_document, label("n_owners", func.count()))
            #     .select_from(q_assocs.group_by(AssocUserDocument.id_document))
            # ) .where( literal_column("n_owners") == 1 )

            # exclusive_documents : List[Document] = list(session.execute(
            #     select(Document).where(Document.id)
            # ).scalars())

            session.delete(user)
            session.commit()

            return user.uuid

    @classmethod
    def post_user(cls, makesession: DependsSessionMaker, user: UserSchema) -> UUID:
        """Create a user.

        User can create collections and documents later during the registration
        flow.
        """

        with makesession() as session:
            session.add(user_obj := User(**user.model_dump()))
            session.commit()
            return user_obj.uuid


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
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthView,
    }

    @classmethod
    def get_index(cls, uuid: int, makesession: DependsSessionMaker) -> None:
        ...
