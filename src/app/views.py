"""Api routers and functions. 

This includes a metaclass so that undecorated functions may be tested.
"""
import logging
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Type

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.routing import APIRoute
from sqlalchemy import select
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
from app.models import Collection, Edit, User
from app.schemas import (
    CollectionSchema,
    DocumentMetadataSchema,
    DocumentSchema,
    EditMetadataSchema,
    EditSchema,
    UserSchema,
)

logger = util.get_logger(__name__)

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


class DocumentView(BaseView):
    view_routes = dict(
        get_document="/",
        post_document="/",
        put_document="/",
        delete_document="/",
        get_document_edits="/edits",
    )

    @classmethod
    def get_document(cls, filter_params):
        ...

    @classmethod
    def get_document_edits(cls, filter_params):
        ...

    @classmethod
    def post_document(cls, filter_params):
        ...

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
        get_user="{uuid}",
        patch_user="{}",
        delete_user="",
        post_user="/register",
        get_user_child="/{child}",
        post_document_access="/{uuid}/grant",
    )

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    @classmethod
    def get_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: DependsUUID,
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
                raise HTTPException(404)
            return result  # type: ignore

    # NOTE: The token depends is included since API billing will depend on
    #       users having a valid token. Later I would like to make it such that
    #       it will also accept requests without tokens from particular
    #       origins, for instance a site where articles may be publicly viewed.
    @classmethod
    def get_users(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        filter: DependsFilter,
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
        uuid: str,
    ) -> (
        List[CollectionSchema] | List[EditMetadataSchema] | List[DocumentMetadataSchema]
    ):
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
            children: List[Collection] | List[Edit] | None
            children = getattr(result, child, None)
            if children is None:
                raise HTTPException(418, detail="This is awkward.")

            return children

    # ----------------------------------------------------------------------- #
    # CRUD without R

    @classmethod
    def patch_user(cls):
        """Update a user."""
        ...

    @classmethod
    def delete_user(cls):
        """Remove a user and their unshared documents and edits."""
        ...

    @classmethod
    def post_user(
        cls,
        # user: UserCreateRequest,
    ):
        """This should be the endpoint that should be used by the login flow."""
        ...

    # ----------------------------------------------------------------------- #
    # Sharing.

    @classmethod
    def post_document_access(
        cls,
        # user: User = Depends(user_from_auth),
        # grant_to_uuid_user: int = 1,
        # grant_level: Literal["read", "write", "owner"],
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
