"""Api routers and functions. 

This includes a metaclass so that undecorated functions may be tested.
"""
import logging
from typing import Any, ClassVar, Dict, Literal, Type

from fastapi import APIRouter, FastAPI
from typing_extensions import Self

from app import util
from app.models import Collection, Document, User

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
            router = (
                T.view_router  # type: ignore
                if hasattr(T, "view_router")
                else APIRouter(**T.view_router_args)  # type: ignore
            )
            for name_fn, route in T.view_routes.items():  # type: ignore
                if "_" not in name_fn:
                    continue

                logger.debug(
                    "Adding `%s` to `%s` router at `%s`.", name_fn, name, route
                )
                http_meth, _ = name_fn.split("_", 1)
                match http_meth:
                    case "get" | "post" | "delete" | "patch" | "put":
                        fn = getattr(T, name_fn, None)
                        if fn is None:
                            msg = f"No such method `{name_fn}` of `{name}`."
                            raise ValueError(msg)
                        getattr(router, http_meth)(route)(fn)
                    case _:
                        logger.debug("Skipping `%s.%s`.", name, name_fn)

            for child_prefix, child in T.view_children.items():  # type: ignore
                logger.debug(
                    "Adding child router `%s` for `%s`.",
                    child_prefix,
                    name,
                )
                router.include_router(child.view_router, prefix=child_prefix)
            T.view_router = router  # type: ignore

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
        get_user="/",
        patch_user="/",
        delete_user="/",
        post_user="/register",
        get_user_child="/{child}/",
        post_document_access="/grant",
    )

    @classmethod
    def get_user(cls, filter_params):
        """Get user metadata.

        For instance, this should be used to make a profile page.
        """
        ...

    # NOTE: Add a ``message`` field to :class:`Edit`.
    @classmethod
    def get_user_child(cls, child: Literal["collections", "edits"], filter_params):
        """Get user ``collections`` and ``edits`` data without content.

        :param child: Child to get metadata for. Must be one of ``collections``
            or ``edits``. For ``documents`` use the ``/document`` endpoints.
        :param filter_params: Use these parameters to filter out which children
            to display.
        """

        ...

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


class Auth0View(BaseView):
    """This is where auth0 will host routes to handle login and getting
    tokens.
    """

    ...


class AppView(BaseView):
    view_routes = {"/": "index"}
    view_children = {
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": Auth0View,
    }

    @classmethod
    def index(cls):
        return "It works!"


# AppView.view_router.include_router(UserView.view_router, prefix="/users")
print(len(UserView.view_router.routes))
print(len(APIRouter().routes))
