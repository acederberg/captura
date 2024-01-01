"""Api routers and functions. 

This includes a metaclass so that undecorated functions may be tested.
"""
import logging
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Type, TypeAlias

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query
from fastapi.params import Param
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
QueryUUIDOwner: TypeAlias = Annotated[List[str], Query(min_length=4, max_length=16)]
QueryUUIDDocument: TypeAlias = Annotated[List[str], Query(min_length=4, max_length=16)]
PathUUID: TypeAlias = Annotated[str, Path()]

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
        cls, makesession: DependsSessionMaker, uuid: PathUUID
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
        uuid: PathUUID,
    ):
        ...

    @classmethod
    def post_document(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        documents: List[DocumentSchema],
        uuid_collection: QueryUUIDCollection = list(),
        uuid_owner: QueryUUIDOwner = list(),
    ):
        uuid = token["uuid"]
        with makesession() as session:
            # Add the documents
            logger.debug("Adding new documents for user `%s`.", uuid)
            session.add_all(
                document_objs := list(
                    Document(**document.model_dump()) for document in documents
                )
            )
            session.commit()
            for document_obj in document_objs:
                session.refresh(document_obj)

            # Add user ownership for documents.
            logger.debug("Defining ownership of new documents.")
            user_uuids = [uuid, *uuid_owner]
            users: List[User] = list(
                session.execute(select(User).where(User.uuid.in_(user_uuids))).scalars()
            )
            assocs_owners = list(
                AssocUserDocument(
                    user_id=user,
                    document_id=document,
                    level="owner",
                )
                for document in documents
                for user in users
            )
            session.add_all(assocs_owners)
            session.commit()

            # Find the collection if necessary
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
                for document in document_objs
                for collection in collections
            )
            session.add_all(assocs_collections)
            session.commit()

            return dict(
                documents={dd.uuid: dd.name for dd in document_objs},
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
        post_document_access="/{uuid}/grant",
    )

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    @classmethod
    def get_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUID,
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
        uuid: PathUUID,
    ) -> Any:
        """Get user ``collections`` and ``edits`` data without content.

        :param child: Child to get metadata for. Must be one of ``collections``
            or ``edits``. For ``documents`` use the ``/document`` endpoints.
        :param filter_params: Use these parameters to filter out which children
            to display.
        """

        with makesession() as session:
            result: None | User = session.execute(
                select(User).where(User.uuid == uuid)
            ).scalar()
            children: List[Collection] | List[Edit] | List[Document] | None
            children = getattr(result, child, None)
            print(child, result)
            if children is None:
                raise HTTPException(418, detail="This is awkward.")

            return children  # type: ignore

    @classmethod
    def get_user_documents(
        cls, makesession: DependsSessionMaker, uuid: PathUUID
    ) -> Dict[str, DocumentMetadataSchema]:
        return cls.select_user_child(
            "documents",
            makesession,
            uuid,
        )

    @classmethod
    def get_user_collections(
        cls, makesession: DependsSessionMaker, uuid: PathUUID
    ) -> Dict[str, CollectionMetadataSchema]:
        return cls.select_user_child(
            "collections",
            makesession,
            uuid,
        )

    @classmethod
    def get_user_edits(
        cls, makesession: DependsSessionMaker, uuid: PathUUID
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
        uuid: PathUUID,
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
            for key, value in updates.model_dump().items():
                if value is None:
                    continue
                setattr(user, key, value)
            session.add(user)
            session.commit()

    @classmethod
    def delete_user(cls, makesession: DependsSessionMaker, uuid: PathUUID) -> UUID:
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

    # ----------------------------------------------------------------------- #
    # Sharing.

    @classmethod
    def post_document_access(
        cls,
        uuid: PathUUID,
        grant_level: Literal["read", "write", "owner"],
        uuid_document: QueryUUIDDocument,
    ) -> None:
        ...

    @classmethod
    def post_collection_assignment(
        cls,
        uuid_document: int,
        uuid_collection: int,
    ) -> None:
        ...


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
