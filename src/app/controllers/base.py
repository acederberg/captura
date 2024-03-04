"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.

"""

from typing import Self
import enum
import logging
from functools import cached_property
from http import HTTPMethod
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    Literal,
    Set,
    Tuple,
    Type,
    TypeVar,
)

from app import __version__, util
from app.auth import Token
from app.models import (
    AnyModel,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindObject,
    Level,
    LevelHTTP,
    ResolvableSingular,
    ResolvedRawAny,
    Singular,
    User,
    uuids,
)
from fastapi import HTTPException
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    Tag,
    ValidationInfo,
    computed_field,
    field_validator,
)
from sqlalchemy.orm import Session

logger = util.get_logger(__name__)
logger.level = logging.INFO


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
    _token_user: User | None

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
        if self._token_user is not None:
            return self._token_user
        token_user = self.token.validate(self.session)
        self._token_user = token_user
        return token_user

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
            case bad:
                raise ValueError(f"Invalid input `{bad}` for token.")

        print("THERE")
        if self._token:
            self._token_user = self._token.validate(session)


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


class KindData(str, enum.Enum):
    event = "event"
    collection = "collection"
    document = "document"
    user = "user"
    edit = "edit"
    assignment_document = "assignment_document"
    assignment_collection = "assignment_collection"
    grant_document = "grant_document"
    grant_user = "grant_user"


class BaseResolved(BaseModel):
    kind: ClassVar[KindData]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        util.check_enum_opt_attr(cls, "kind", KindData)


class BaseResolvedPrimary(BaseResolved):

    _items_attr_name: ClassVar[str]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        cls._items_attr_name = Singular(cls.kind.name).name

        # NOTE: How to check that a particular field is defined? `model_fields`
        #       is empty here but not when using the class otherwise. A
        #       solution without metaclasses is strongly preffered.
        #       This is nice to have because it verifies that
        #       ``_items_attr_name`` is an actual field.

        # field_name = Singular(cls.kind.name).name
        # if field_name not in cls.model_fields:
        #     msg = f"`{cls.__name__}` should have field `{field_name}`. "
        #     msg += f"`{cls.model_fields}`."
        #     raise ValueError(msg)
        # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    def err_nonempty(self) -> ValueError | None:

        # It is empty
        if not len(getattr(self, attr_name := self._items_attr_name)):
            return None

        name = self.__class__.__name__
        msg = f"Primary data `{name}` should be empty (in field "
        msg += f"`{attr_name}`)."
        return ValueError(msg)

    @classmethod
    def empty(cls, **kwargs_init) -> Self:
        return cls(**{cls._items_attr_name: tuple()}, **kwargs_init)



class BaseResolvedSecondary(BaseResolved):
    kind: ClassVar[KindData]
    kind_source: ClassVar[KindObject]
    kind_target: ClassVar[KindObject]
    kind_assoc: ClassVar[KindObject]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        util.check_enum_opt_attr(cls, "kind_source", KindObject)
        util.check_enum_opt_attr(cls, "kind_target", KindObject)
        util.check_enum_opt_attr(cls, "kind_assoc", KindObject)

    @computed_field
    @property
    def source(self) -> Document:
        return getattr(self, self.kind_source.name)

    @computed_field
    @property
    def target(self) -> Tuple[Collection, ...]:
        return getattr(self, Singular(self.kind_target.name).name)

    @computed_field
    @property
    def uuid_source(self) -> str:
        return getattr(self, "uuid_" + self.kind_source.name)

    @computed_field
    @property
    def uuid_target(self) -> Set[str]:
        return getattr(self, "uuid_" + Singular(self.kind_target.name).name)


class ResolvedCollection(BaseResolvedPrimary):
    kind = KindData.collection

    collections: Tuple[Collection, ...]
    uuid_collections: UuidSetFromModel


class ResolvedDocument(BaseResolvedPrimary):
    kind = KindData.document

    documents: Tuple[Document, ...]
    uuid_documents: UuidSetFromModel

    token_user_grants: Dict[str, Grant]


class ResolvedEdit(BaseResolvedPrimary):
    kind = KindData.edit

    edits: Tuple[Edit, ...]
    uuid_edit: UuidSetFromModel

    token_user_grants: Dict[str, Grant]


class ResolvedUser(BaseResolvedPrimary):
    kind = KindData.user

    users: Tuple[User, ...]
    uuid_users: UuidSetFromModel


class ResolvedEvent(BaseResolvedPrimary):
    kind = KindData.event

    events: Tuple[Event, ...]
    uuid_events: UuidSetFromModel


class ResolvedObjectEvents(ResolvedEvent):
    # kind = KindData.event
    #
    # events: Tuple[Event, ...]
    # uuid_events: UuidSetFromModel

    obj: Annotated[AnyModel, Field()]
    uuid_obj: UuidFromModel
    kind_obj: Annotated[KindObject, Field()]


class ResolvedGrantUser(BaseResolvedSecondary):
    kind = KindData.grant_user
    kind_source = KindObject.user
    kind_target = KindObject.document
    kind_assoc = KindObject.grant

    user: User
    documents: Tuple[Document, ...]
    uuid_user: UuidFromModel
    uuid_documents: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_user` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]


class ResolvedGrantDocument(BaseResolvedSecondary):
    kind = KindData.grant_document
    kind_source = KindObject.document
    kind_target = KindObject.user
    kind_assoc = KindObject.grant

    document: Document
    users: Tuple[User, ...]
    uuid_document: UuidFromModel
    uuid_users: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_document` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]


class ResolvedAssignmentCollection(BaseResolvedSecondary):
    kind = KindData.assignment_collection
    kind_source = KindObject.collection
    kind_target = KindObject.document
    kind_assoc = KindObject.assignment

    collection: Collection
    # assignments: Dict[str, Assignment]
    documents: Tuple[Document, ...]
    uuid_collection: UuidFromModel
    uuid_documents: UuidSetFromModel

    # These are very helpful for handling cases in general


class ResolvedAssignmentDocument(BaseResolvedSecondary):
    kind = KindData.assignment_document
    kind_source = KindObject.document
    kind_target = KindObject.collection
    kind_assoc = KindObject.assignment

    document: Document
    # assignments: Dict[str, Assignment]
    collections: Tuple[Collection, ...]
    uuid_document: UuidFromModel
    uuid_collections: UuidSetFromModel


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
    Annotated[ResolvedEvent, Tag("event")],
    Annotated[ResolvedObjectEvents, Tag("object_events")],
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
    @property
    def kind(self) -> KindData:
        return self.data.kind

    def types(self) -> Any:
        return kind_type_map[self.kind]  # type: ignore[return-type]


DataResolvedAssignment = (
    Data[ResolvedAssignmentCollection] | Data[ResolvedAssignmentDocument]
)
DataResolvedGrant = Data[ResolvedGrantUser] | Data[ResolvedGrantDocument]