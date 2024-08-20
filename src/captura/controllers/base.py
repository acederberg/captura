"""Api routers and functions. 

This includes a metaclass so that undecorated functions may be tested.

"""

# =========================================================================== #
import enum
import logging
from functools import cached_property
from http import HTTPMethod
from traceback import print_tb
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Literal,
    Self,
    Set,
    Tuple,
    Type,
    TypeAlias,
    TypeVar,
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

# --------------------------------------------------------------------------- #
from captura import util
from captura.auth import Token
from captura.fields import LevelHTTP, Singular
from captura.models import (
    AnyModel,
    Assignment,
    Base,
    Collection,
    Document,
    Event,
    Grant,
    KindObject,
    Level,
    ResolvableSingular,
    User,
    resolve_model,
    uuids,
)

logger = util.get_logger(__name__)
logger.level = logging.INFO


T_BaseController = TypeVar("T_BaseController", bound="BaseController")


class BaseController:
    """Base for :class:`Access`, :class:`Delete`, etc.

    :attr method: The ``http.HTTPMethod``. In some controllers this will be
        constant. In the access controller this will be used to check the
        levels of grants required to perform particular operations.
    :attr session: A ``Session``.
    :attr token: A ``Token``.
    """

    method: HTTPMethod
    session: Session
    _token: Token | None
    _token_user: User | None

    @property
    def level(self) -> Level:
        return LevelHTTP[self.method.name].value

    # TODO: Move  `token_user` and `user` to `Data`.
    @cached_property
    def token(self) -> Token:
        if self._token is None:
            raise HTTPException(401, detail="Token required.")
        return self._token

    @cached_property
    def token_user(self) -> User:
        if self._token_user is not None:
            return self._token_user
        token_user = self.token.validate_db(self.session)

        self._token_user = token_user
        return token_user

    # TODO: Rename this function.
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
        self._token_user = None

        match method:
            case str() if method in HTTPMethod._member_map_:
                self.method = HTTPMethod(method)
            case HTTPMethod():
                self.method = method
            case _:
                msg = f"Invalid input `{method}` for parameter `method`."
                raise ValueError(msg)

        match token:
            case dict() | None as raw:
                self._token = None if raw is None else Token.model_validate(raw)
            case Token() as token:
                self._token = token
            case bad:
                msg = f"Invalid input `{bad}` for parameter `token`."
                raise ValueError(msg)


def _uuid_set_from_model(
    data: Any,
    info: ValidationInfo,
    *,
    optional: bool = True,
) -> Set[str] | None:
    if data is not None:
        return data

    data_key = info.field_name
    if data_key is None:
        raise ValueError("WTF")

    data_key_source = data_key.replace("uuid_", "")
    if data_key_source not in info.data:
        raise ValueError(f"Invalid source `{data_key_source}` for uuids.")

    match info.data[data_key_source]:
        case None if optional:
            return None
        case tuple() as resolved:
            return uuids(resolved)  # type: ignore[type-var]
        case dict() as resovled:
            return uuids(tuple(resovled.values()))  # type: ignore[type-var]
        case Base() as other:
            return {other.uuid}
        case bad:
            return bad


def uuid_set_from_model(
    data: Any,
    info: ValidationInfo,
) -> Set[str]:
    res = _uuid_set_from_model(data, info)
    if res is None:
        raise ValueError()
    return res


def uuid_set_from_model_optional(
    data: Any,
    info: ValidationInfo,
) -> Set[str] | None:
    res = _uuid_set_from_model(data, info)
    return res


def uuid_from_model(data: Any, info: ValidationInfo) -> str:
    if data is not None:
        return data
    res = uuid_set_from_model(data, info)
    return res.pop()


UuidSetFromModelOptional = Annotated[
    Set[str] | None,
    Field(default=None, validate_default=True),
    BeforeValidator(uuid_set_from_model_optional),
]
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
    object_event = "object_event"
    event = "event"
    collection = "collection"
    document = "document"
    user = "user"
    edit = "edit"
    assignment_document = "assignment_document"
    assignment_collection = "assignment_collection"
    grant_document = "grant_document"
    grant_user = "grant_user"


ResolvableKindData: TypeAlias = KindData | KindObject | Tuple[KindObject, KindObject]


def resolve_kind_data(v: ResolvableKindData) -> KindData:
    match v:
        case KindData():
            return v
        case (
            KindObject.user
            | KindObject.collection
            | KindObject.edit
            | KindObject.document as kind
        ):
            return KindData(kind.name)
        case KindObject() as bad:
            msg = f"Cannot resolve scalar `KindObject` `{bad.name}`."
            raise ValueError(msg)
        case (KindObject.user, KindObject.document):
            return KindData.grant_user
        case (KindObject.document, KindObject.user):
            return KindData.grant_document
        case (KindObject.document, KindObject.collection):
            return KindData.assignment_document
        case (KindObject.collection, KindObject.document):
            return KindData.assignment_collection
        case (a, b):
            msg = f"Cannot resolve vector `KindObject` `({a.name}, {b.name})`."
            raise ValueError(msg)
        case _:
            raise ValueError(f"Cannot resolve `{v}`.")


def resolve_kind_assoc(v: KindData) -> Literal[KindObject.assignment, KindObject.grant]:
    match v:
        case KindData.grant_user | KindData.grant_document:
            return KindObject.grant
        case KindData.assignment_document | KindData.assignment_collection:
            return KindObject.assignment
        case bad:
            raise ValueError(f"Cannot resolve assoc for data kind `{bad}`.")


class BaseResolved(BaseModel):
    kind: ClassVar[KindData]
    registry: ClassVar[Dict[KindData, "Type[BaseResolved]"]] = dict()

    delete: bool = False
    _attr_name_targets: ClassVar[str]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        util.check_enum_opt_attr(cls, "kind", KindData)
        if cls.kind in cls.registry:
            cls_existing = cls.registry[cls.kind].__name__
            raise ValueError(
                f"`registry` already has a resolved class `{cls_existing}` for"
                f"`{cls.kind}`. There should be exactly one class marked with "
                "any given kind."
            )
        cls.registry[cls.kind] = cls

    def register(self, session: Session) -> None: ...

    def refresh(self, session: Session) -> None: ...

    @classmethod
    def get(cls, resolvable_kind: ResolvableKindData) -> "Type[BaseResolved]":
        kind_data = resolve_kind_data(resolvable_kind)
        return BaseResolved.registry[kind_data]

    @classmethod
    def empty(cls, **kwargs_init) -> Self:
        "Yes, I know an ABC could be used here."
        raise ValueError("Not implemented!")


T_ResolvedPrimary = TypeVar("T_ResolvedPrimary", User, Collection, Document)


class BaseResolvedPrimary(BaseResolved):
    # ----------------------------------------------------------------------- #

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        if cls.kind == KindData.object_event:
            cls._attr_name_targets = "events"
        else:
            cls._attr_name_targets = Singular(cls.kind.name).name

        # NOTE: How to check that a particular field is defined? `model_fields`
        #       is empty here but not when using the class otherwise. A
        #       solution without metaclasses is strongly preffered.
        #       This is nice to have because it verifies that
        #       ``_attr_name_targets`` is an actual field.

        # field_name = Singular(cls.kind.name).name
        # if field_name not in cls.model_fields:
        #     msg = f"`{cls.__name__}` should have field `{field_name}`. "
        #     msg += f"`{cls.model_fields}`."
        #     raise ValueError(msg)
        # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    @classmethod
    def empty(cls, **kwargs_init) -> Self:
        return cls(**{cls._attr_name_targets: tuple()}, **kwargs_init)

    # ----------------------------------------------------------------------- #

    def targets(self) -> Tuple[Any, ...]:
        return getattr(self, self._attr_name_targets)

    def err_nonempty(self) -> ValueError | None:
        # It is empty
        if not len(getattr(self, attr_name := self._attr_name_targets)):
            return None

        name = self.__class__.__name__
        msg = f"Primary data `{name}` should be empty (in field "
        msg += f"`{attr_name}`)."
        return ValueError(msg)

    def register(self, session: Session) -> None:
        """Because writing commit/refresh logic and wrapping to avoid breaking
        'all or none'.
        """

        if self.delete:
            return

        # NOTE: DO NOT COMMIT HERE! Commits occurs in `data.commit`
        targets = self.targets()
        session.add_all(targets)

    def refresh(self, session: Session) -> None:
        if self.delete:
            return

        for target in self.targets():
            session.refresh(target)


class BaseResolvedSecondary(BaseResolved):
    kind: ClassVar[KindData]
    kind_source: ClassVar[KindObject]
    kind_target: ClassVar[KindObject]
    kind_assoc: ClassVar[KindObject]
    _attr_name_source: ClassVar[str]
    _attr_name_assoc: ClassVar[str]
    _attr_name_target: ClassVar[str]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        util.check_enum_opt_attr(cls, "kind_source", KindObject)
        util.check_enum_opt_attr(cls, "kind_target", KindObject)
        util.check_enum_opt_attr(cls, "kind_assoc", KindObject)
        cls._attr_name_source = cls.kind_source.name
        cls._attr_name_target = Singular(cls.kind_target.name).name
        cls._attr_name_assoc = Singular(cls.kind_assoc.name).name

    @classmethod
    def get_model(cls, for_: Literal["assoc", "target", "source"] = "assoc") -> Type:
        kind = getattr(cls, f"kind_{for_}")
        return resolve_model(kind)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source(self) -> Document | User | Collection:
        return getattr(self, self._attr_name_source)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target(self) -> Tuple[Collection, ...]:
        return getattr(self, self._attr_name_target)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def assoc(self) -> Dict[str, Any]:
        return getattr(self, self._attr_name_assoc)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def uuid_source(self) -> str:
        return getattr(self, "uuid_" + self._attr_name_source)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def uuid_target(self) -> Set[str]:
        return getattr(self, "uuid_" + self._attr_name_target)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def uuid_assoc(self) -> Set[str]:
        return getattr(self, "uuid_" + self._attr_name_assoc)

    def register(self, session: Session) -> None:
        """Because writing commit/refresh logic and wrapping to avoid breaking
        'all or none' of ACID.
        """
        # NOTE: Should not add targets or sources since they should not
        #       be modified in any of the functions that accept this `kind`
        #       of data. Instead, child data should be appended to data.

        if self.delete:
            return

        if self.assoc:
            session.add_all(self.assoc.values())

    def refresh(self, session: Session) -> None:
        if self.delete:
            return
        if not self.assoc:
            return

        for assoc in self.assoc.values():
            if assoc in session.deleted:
                continue
            session.refresh(assoc)


class ResolvedCollection(BaseResolvedPrimary):
    kind = KindData.collection

    collections: Tuple[Collection, ...]
    uuid_collections: UuidSetFromModel


class ResolvedDocument(BaseResolvedPrimary):
    kind = KindData.document

    documents: Tuple[Document, ...]
    uuid_documents: UuidSetFromModel

    token_user_grants: Dict[str, Grant]


class Resolved(BaseResolvedPrimary):
    kind = KindData.edit

    uuid_edits: UuidSetFromModel

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
    kind = KindData.object_event
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
    grants: Annotated[
        Dict[str, Grant],
        Field(
            description="A map from `document` uuids to their respective `grant`s for `user`."
        ),
    ]
    uuid_user: UuidFromModel
    uuid_documents: UuidSetFromModel
    uuid_grants: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_user` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]

    # TODO: Add TypedDict for these kwargs.
    # def grants(self, session: Session, **kwargs) -> Tuple[Grant, ...]:
    #     q = self.user.q_select_grants(self.uuid_documents, **kwargs)
    #     return tuple(session.execute(q).scalars())


class ResolvedGrantDocument(BaseResolvedSecondary):
    kind = KindData.grant_document
    kind_source = KindObject.document
    kind_target = KindObject.user
    kind_assoc = KindObject.grant

    document: Document
    users: Tuple[User, ...]
    grants: Annotated[
        Dict[str, Grant],
        Field(
            description="A map from `user` uuids to their respective `grant`s for `document`."
        ),
    ]
    uuid_document: UuidFromModel
    uuid_users: UuidSetFromModel
    uuid_grants: UuidSetFromModel

    # NOTE: See note inside of `Access.grant_document` about `token_user_grants`.
    token_user_grants: Dict[str, Grant]

    # TODO: Add TypedDict for these kwargs.
    # def grants(self, session: Session, **kwargs) -> Tuple[Grant, ...]:
    #     q = self.document.q_select_grants(self.uuid_users, **kwargs)
    #     return tuple(session.execute(q).scalars())


class ResolvedAssignmentCollection(BaseResolvedSecondary):
    kind = KindData.assignment_collection
    kind_source = KindObject.collection
    kind_target = KindObject.document
    kind_assoc = KindObject.assignment

    collection: Collection
    assignments: Dict[str, Assignment]
    documents: Tuple[Document, ...]
    uuid_collection: UuidFromModel
    uuid_assignments: UuidSetFromModelOptional
    uuid_documents: UuidSetFromModel

    # These are very helpful for handling cases in general


class ResolvedAssignmentDocument(BaseResolvedSecondary):
    kind = KindData.assignment_document
    kind_source = KindObject.document
    kind_target = KindObject.collection
    kind_assoc = KindObject.assignment

    document: Document
    assignments: Dict[str, Assignment]
    collections: Tuple[Collection, ...]
    uuid_document: UuidFromModel
    uuid_assignments: UuidSetFromModelOptional
    uuid_collections: UuidSetFromModel


T_Data = TypeVar(
    "T_Data",
    Annotated[ResolvedCollection, Tag("collection")],
    Annotated[ResolvedDocument, Tag("document")],
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
    children: Annotated["List[Data]", Field(default_factory=list)]

    @field_validator("data", mode="before")
    def validate_raw(cls, v):
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def kind(self) -> KindData:
        return self.data.kind

    # @property
    # def resolved_cls(self) -> T_Data:
    #     return self.data.__class__

    # ----------------------------------------------------------------------- #

    def empty(self, kind_data: KindData | str, **kwargs_init) -> Self:
        "Make an empty version of self (same data, resolved is empty)."

        if isinstance(kind_data, str):
            kind_data = KindData[kind_data]

        T_Resolved = BaseResolved.registry[kind_data]
        mt = T_Resolved.empty(**kwargs_init)
        return self.__class__(
            data=mt,  # type: ignore
            event=self.event,
            token_user=self.token_user,
            children=list(),
        )

    def add(self, *items: "Data") -> None:
        for item in items:
            self.children.append(item)

    def register(self, session: Session) -> None:
        self.data.register(session)
        if self.event is not None:
            session.add(self.event)

        for child in self.children:
            child.register(session)

    def refresh(self, session: Session) -> None:
        # session.expire_all()
        self.data.refresh(session)
        if self.event is not None:
            session.refresh(self.event)
        for child in self.children:
            child.refresh(session)

    def commit(self, session: Session, commit: Any = None) -> None:
        if commit is not None:
            logger.warning("The `commit` argument is being removed.")
        self.register(session)
        try:
            session.commit()
        except Exception as err:
            print_tb(err.__traceback__)
            util.CONSOLE_APP.print("[red]" + str(err))
            session.rollback()
            raise HTTPException(500, "Database commit failure.")

        self.refresh(session)

    def types(self) -> Any:
        return kind_type_map[self.kind]  # type: ignore[return-type]


#
# T_OutputKind = TypeVar("T_OutputKind", AsOutput, OutputWithEvents)
# T_Output
#
# def primary_output(
#     data: Data[T_Data_Singular],
#     T_output_kind: T_OutputKind,
#     T_output: T_Output,
# ) -> Data[T_Data_


DataResolvedAssignment = (
    Data[ResolvedAssignmentCollection] | Data[ResolvedAssignmentDocument]
)
DataResolvedGrant = Data[ResolvedGrantUser] | Data[ResolvedGrantDocument]
