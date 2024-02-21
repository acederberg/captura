"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.

"""

import enum
import logging
from functools import cached_property
from http import HTTPMethod
from os import walk
from typing import (Annotated, Any, ClassVar, Dict, Generic, Literal, Set,
                    Tuple, Type, TypeAlias, TypeVar, Union)

from app import __version__, util
from app.auth import Token
from app.config import Config
from app.depends import DependsToken
from app.models import (AnyModel, Assignment, Base, Collection, Document, Edit,
                        Event, Grant, KindEvent, KindObject, Level, LevelHTTP,
                        Resolvable, ResolvableMultiple, ResolvableSingular,
                        ResolvedRawAny, Singular, User, uuids)
from fastapi import APIRouter, HTTPException
from fastapi.routing import APIRoute
from pydantic import (BaseModel, BeforeValidator, ConfigDict, Discriminator,
                      Field, RootModel, Tag, ValidationInfo, computed_field,
                      field_validator)
from pydantic_core.core_schema import FieldValidationInfo
from sqlalchemy.orm import Session

logger = util.get_logger(__name__)
logger.level = logging.INFO

# =========================================================================== #
# Controllers

T_BaseController = TypeVar("T_BaseController", bound="BaseController")


class BaseController:
    """This is going to be required.

    :attr method: The ``http.HTTPMethod``. In some controllers this will be
        constant. In the access controller this will be used to check the
        levels of grants required to perform particular operations.
    :attr session: A ``Session``.
    :attr token: A ``_token``.
    """

    method: HTTPMethod
    session: Session
    _token: Token | None

    @property
    def level(self) -> Level:
        return LevelHTTP[self.method.name].value

    @cached_property
    def token(self) -> Token:
        if self._token is None:
            raise HTTPException(401, detail="Token required.")
        return self._token

    @cached_property
    def token_user(self) -> User:
        return User.if_exists(self.session, self.token.uuid)

    def then(self, type_: Type[T_BaseController], **kwargs) -> T_BaseController:
        "For chainable controllers."
        return type_(self.session, self._token, self.method, **kwargs)

    def token_user_or(
        self,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> User:
        return (
            User.resolve(self.session, resolve_user)
            if resolve_user is not None
            else self.token_user
        )

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
    ):
        self.session = session
        match method:
            case str():
                self.method = HTTPMethod(method)
            case HTTPMethod():
                self.method = method
            case _:
                raise ValueError(f"Invalid input `{method}` for method.")

        match token:
            case dict() | None as raw:
                self._token = None if raw is None else Token.model_validate(raw)
            case Token() as token:
                self._token = token


def uuid_set_from_model(data: Any, info: ValidationInfo) -> Set[str]:
    if data is not None:
        return data

    data_key = info.field_name
    if data_key is None:
        raise ValueError("WTF")

    data_key_source = data_key.replace("uuid_", "")
    if data_key_source not in info.data:
        raise ValueError(f"Invalid source `{data_key_source}` for uuids.")
    data_source = info.data[data_key_source]
    res = uuids(data_source)
    return res


def uuid_from_model(data: Any, info: ValidationInfo) -> str:
    if data is not None:
        return data
    res = uuid_set_from_model(data, info)
    return res.pop()


UuidSetFromModel = Annotated[
    Set[str],
    Field(default=None, validate_default=True),
    BeforeValidator(uuid_set_from_model),
]
UuidFromModel = Annotated[
    str,
    Field(default=None, validate_default=True),
    BeforeValidator(uuid_from_model),
]


class BaseResolved(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)


class BaseResolvedAssoc(BaseResolved):
    kind_source: Any
    kind_target: Any
    kind_assoc: Any

    @computed_field
    def source(self) -> Document:
        return getattr(self, self.kind_source.name)

    @computed_field
    def target(self) -> Tuple[Collection, ...]:
        return getattr(self, Singular(self.kind_target.name).name)

    @computed_field
    def uuid_source(self) -> str:
        return getattr(self, "uuid_" + self.kind_source.name)

    @computed_field
    def uuid_target(self) -> Set[str]:
        return getattr(self, "uuid_" + Singular(self.kind_target.name).name)


class ResolvedCollection(BaseResolved):
    kind: Annotated[Literal["collection"], Field(default="collection")]

    collections: Tuple[Collection, ...]
    uuid_collections: UuidSetFromModel


class ResolvedDocument(BaseResolved):
    kind: Annotated[Literal["document"], Field(default="document")]

    documents: Tuple[Document, ...]
    uuid_documents: UuidSetFromModel

    token_user_grants: Dict[str, Grant]


class ResolvedEdit(BaseResolved):
    kind: Annotated[Literal["edit"], Field(default="edit")]

    edits: Tuple[Edit, ...]
    uuid_edit: UuidSetFromModel

    token_user_grants: Dict[str, Grant]


class ResolvedUser(BaseResolved):
    kind: Annotated[Literal["user"], Field(default="user")]

    users: Tuple[User, ...]
    uuid_users: UuidSetFromModel


class ResolvedGrantUser(BaseResolvedAssoc):
    kind: Annotated[Literal["grant_user"], Field(default="grant_user")]
    kind_source: Annotated[
        Literal[KindObject.user], Field(default=KindObject.user)
    ]
    kind_target: Annotated[
        Literal[KindObject.document],
        Field(default=KindObject.document),
    ]
    kind_assoc: Annotated[
        Literal[KindObject.grant],
        Field(default=KindObject.grant),
    ]

    user: User
    documents: Tuple[Document, ...]
    uuid_user: UuidFromModel
    uuid_documents: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_user` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]

class ResolvedGrantDocument(BaseResolvedAssoc):
    kind: Annotated[Literal["grant_document"], Field(default="grant_document")]
    kind_source: Annotated[
        Literal[KindObject.document],
        Field(default=KindObject.document),
    ]
    kind_target: Annotated[
        Literal[KindObject.user],
        Field(default=KindObject.user),
    ]
    kind_assoc: Annotated[
        Literal[KindObject.grant],
        Field(default=KindObject.grant),
    ]

    document: Document
    users: Tuple[User, ...]
    uuid_document: UuidFromModel
    uuid_users: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_document` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]

class ResolvedAssignmentCollection(BaseResolvedAssoc):
    kind: Annotated[
        Literal["assignment_collection"],
        Field(default="assignment_collection"),
    ]
    kind_source: Annotated[
        Literal[KindObject.collection],
        Field(default=KindObject.collection),
    ]
    kind_target: Annotated[
        Literal[KindObject.document],
        Field(default=KindObject.document),
    ]
    kind_assoc: Annotated[
        Literal[KindObject.assignment],
        Field(default=KindObject.assignment),
    ]

    collection: Collection
    # assignments: Dict[str, Assignment]
    documents: Tuple[Document, ...]
    uuid_collection: UuidFromModel
    uuid_documents: UuidSetFromModel

    # These are very helpful for handling cases in general


class ResolvedAssignmentDocument(BaseResolvedAssoc):
    kind: Annotated[
        Literal["assignment_document"],
        Field(default="assignment_document"),
    ]
    kind_source: Annotated[
        Literal[KindObject.document],
        Field(default=KindObject.document),
    ]
    kind_target: Annotated[
        Literal[KindObject.collection],
        Field(default=KindObject.collection),
    ]
    kind_assoc: Annotated[
        Literal[KindObject.assignment],
        Field(default=KindObject.assignment),
    ]

    document: Document
    # assignments: Dict[str, Assignment]
    collections: Tuple[Collection, ...]
    uuid_document: UuidFromModel
    uuid_collections: UuidSetFromModel


class KindData(enum.Enum):
    user: User
    collection: ResolvedCollection
    document: ResolvedDocument
    edit: ResolvedEdit
    grant_user: ResolvedGrantUser
    grant_document: ResolvedGrantDocument
    assignment_collection: ResolvedAssignmentCollection
    assignment_document: ResolvedAssignmentDocument

    # Resolve the tag for any data. Tags should match corresponding functions for
    # types.
    @classmethod
    def discriminate_raw(cls, v: ResolvedRawAny) -> str | None:
        match v:
            case Collection() | Document() | User() | Edit() as row:
                # Map tablename to singular name.
                return Singular[row.__tablename__].value
            # Check assignments
            case (Collection(), (Document(), *_)):
                return "assingment_collection"
            case (Document(), (Collection(), *_)):
                return "assignment_document"
            # Check grants
            case (Document(), (User(), *_)):
                return "grant_user"
            case (User(), (Document(), *_)):
                return "grant_document"
            # If tuple not matching above, look at items inside.
            case (_ as item, *_):
                return cls.discriminate_raw(item)
            case _:
                return None


T_Data = TypeVar(
    "T_Data",
    Annotated[ResolvedCollection, Tag("collection")],
    Annotated[ResolvedDocument, Tag("document")],
    Annotated[ResolvedEdit, Tag("edit")],
    Annotated[ResolvedUser, Tag("user")],
    Annotated[ResolvedAssignmentCollection, Tag("assignment_collection")],
    Annotated[ResolvedAssignmentDocument, Tag("assignment_document")],
    Annotated[ResolvedGrantUser, Tag("grant_user")],
    Annotated[ResolvedGrantDocument, Tag("grant_document")],
)

kind_type_map = dict(
    user=User,
    collection=Collection,
    document=Document,
    edit=Edit,
    grant_user=(User, Document),
    grant_document=(Document, User),
    assignment_collection=(Collection, Document),
    assignment_document=(Document, Collection),
)


class Data(BaseModel, Generic[T_Data]):
    """Because writing out complicated arguments is hard and composition will
    be simplified.

    :class:`Access` will resolve arguments which will be put into here. The
    other controller will then pass the data around so that signatures are
    not so nasty as `Access`, which will take in data, modify it appropriately
    (by performing CRUD and adding events to `Data` and return `Data`).

    This will allow any additional controllers to be sandwiched
    between with the sole requirement being that they match the following
    signature:

    .. code:: text

        (self, data: Data) -> Data

    For documentation of tagged unions, see
    https://docs.pydantic.dev/latest/concepts/unions/#discriminated-unions-with-callable-discriminator
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    data: T_Data
    event: Annotated[Event | None, Field(default=None)]
    token_user: Annotated[User | None, Field(default=None)]

    @field_validator("data", mode="before")
    def validate_raw(cls, v):
        return v

    @computed_field
    def kind(self) -> str:
        return self.data.kind

    def types(self) -> Any:
        return kind_type_map[self.kind]  # type: ignore[return-type]


DataResolvedAssignment = (
    Data[ResolvedAssignmentCollection] | Data[ResolvedAssignmentDocument]
)
DataResolvedGrant = Data[ResolvedGrantUser] | Data[ResolvedGrantDocument]


# =========================================================================== #
# Views


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

        # Parse name
        raw, _ = name_fn.split("_", 1)
        http_meth = next((hh for hh in HTTPMethod if hh.value.lower() == raw), None)
        if http_meth is None:
            logger.warning(f"Could not determine method of `{name_fn}`.")
            return

        # Find attr
        fn = getattr(T, name_fn, None)
        if fn is None:
            msg = f"No such method `{name_fn}` of `{name}`."
            raise ValueError(msg)

        # Create decorator kwargs
        kwargs = dict()
        if http_meth == HTTPMethod.POST:
            kwargs.update(status_code=201)

        # kwargs.update(views_route_args)

        # Get the decoerator and call it.
        logger.debug("Adding function `%s` at route `%s`.", fn.__name__, route)
        decorator = getattr(T.view_router, http_meth.value.lower())
        decorator(route, **kwargs)(fn)

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


class BaseView(ViewMixins, metaclass=ViewMeta): ...
