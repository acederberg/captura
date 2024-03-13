"""Note: None of these schemas should include ``id`` fields. Instead they 
should return UUID fields. This is done because, by design, the UUIDS of 
objects must known if they are to be got. Take for instance the following flow:

1. The ``GET /user`` endpoint gets a users UUID from their JWT. The uuid is 
    sent in the response.
2. The ``GET /user/collections`` endpoint returns the collections for the user 
   returned from the above request.
3. The ``GET /collections/<collection_id>/documents`` endpoint can be used to 
   get some UUIDs to make queries to the document collection.

From a mathmatical standpoint, this is 'good enough' because UUIDs should map
uniquely to a corresponding database row (further, for tables with multiple 
foreign keys it is not necessary to specify multiple values).
"""

import enum
import secrets
from datetime import datetime, timedelta
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Literal,
    Optional,
    Self,
    Set,
    Type,
    TypeAlias,
    TypeVar,
)

from fastapi import Body, Query
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core.core_schema import FieldValidationInfo

from app import models
from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
)
from app.util import check_enum_opt_attr

# --------------------------------------------------------------------------- #

UUID = Annotated[
    str,
    _FieldUUID := Field(
        min_length=4,
        max_length=16,
        description="Universally unique identifier for an object.",
        examples=[secrets.token_urlsafe(8) for _ in range(10)],
    ),
]
UUIDOptional = Annotated[str | None, _FieldUUID]

UnixTimestamp = Annotated[
    None | int,
    Field(
        description="Unix timestamp.",
        examples=[int(datetime.now().timestamp())],
    ),
]
UnixTimestampOptional: TypeAlias = Annotated[
    datetime | None,
    Field(
        default=None,
        description="Optional unix timestamp.",
    ),
]

Name = Annotated[
    str,
    Field(
        min_length=1,
        max_length=LENGTH_NAME,
        description="Object name.",
        examples=["New Mexican Recipes", "Trails", "Software"],
    ),
]
Description = Annotated[
    str,
    Field(
        min_length=1,
        max_length=LENGTH_DESCRIPTION,
        description="Object description",
        examples=["This is a document/user/collection description."],
    ),
]
Url = Annotated[
    str | None,
    Field(
        min_length=8,
        max_length=LENGTH_URL,
        description="User url.",
        examples=["https://github.com/acederberg"],
    ),
]
Content = Annotated[
    str,
    Field(
        max_length=LENGTH_CONTENT,
        description="Document content.",
        examples=[
            "orem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        ],
    ),
]
Format = Annotated[
    models.Format,
    Field(default=models.Format.md, description="Document format."),
]
Message = Annotated[
    str,
    Field(
        min_length=0,
        max_length=LENGTH_MESSAGE,
        description="Edit message.",
        examples=["The following changes were made to the document: ..."],
    ),
]
UUIDS = Annotated[
    Set[str] | None,
    Field(
        default=None,
        description="UUIDs to filter with.",
        examples=[set(secrets.token_urlsafe() for _ in range(25))],
    ),
]
ID = Annotated[int, Field(description="Primary key(s) for tables.")]

Pending = Annotated[
    bool,
    Field(description="Grant awaiting approval (or not)."),
]
PendingFrom = Annotated[
    models.PendingFrom,
    Field(description="Grant initiator."),
]
Deleted = Annotated[
    bool,
    Field(description="Object pending deletion or not."),
]
Detail = Annotated[
    str | None,
    Field(default=None, description="Event detail."),
]
LimitOptional: TypeAlias = Annotated[int | None, Field(default=None)]
NameLike = Annotated[
    str | None,
    Field(
        description="Search objects for a name like this.",
        examples=["foobar", "billy mays"],
    ),
]
DescriptionLike = Annotated[
    str | None,
    Field(
        description="Search objects for a description like this.",
        examples=["dolor sit amit,"],
    ),
]
Level = Annotated[models.Level, Field(description="Access level for grant.")]
KindEvent = Annotated[
    models.KindEvent | None,
    Field(
        default=None,
        description="Event opperation tag.",
    ),
]
KindObject = Annotated[
    models.KindObject | None,
    Field(
        default=None,
        description="Target object type. Often this is the name of corresponding table.",
        examples=[
            models.KindObject.user,
            models.KindObject.collection,
            models.KindObject.document,
        ],
    ),
]


# NOTE: Could use partials but I like this pattern more.
def create_validate_datetime(delta: timedelta) -> BeforeValidator:
    def validator(v: Any, field_info: FieldValidationInfo) -> Any:
        if v:
            return v

        utcnow = datetime.utcnow()
        return utcnow - delta

    return BeforeValidator(validator)


# --------------------------------------------------------------------------- #


class KindSchema(str, enum.Enum):
    search = "search"
    metadata = "metadata"
    default = "default"
    extra = "extra"
    create = "create"
    update = "update"


class KindNesting(str, enum.Enum):
    array = "list"
    object = "dict"


# --------------------------------------------------------------------------- #


class Registry:

    schemas: Dict[KindObject, Dict[KindSchema, Type["BaseSchema"]]]

    def __init__(self):
        self.schemas = dict()

    def add(self, schema: Type["BaseSchema"]):
        kind, kind_schema = schema.kind_mapped, schema.kind_schema
        schemas = self.schemas

        if kind not in schemas:
            schemas[kind] = {kind_schema: schema}
            return

        schemas_for_kind = schemas[kind]
        if kind_schema in schemas_for_kind:
            msg = f"Registry already has value for `{kind} -> {kind_schema}`."
            msg += f"`(existing value = {schemas_for_kind[kind_schema]}`"
            msg += f"`overwritting_value = {schema}`)."
            raise ValueError(msg)

        schemas_for_kind[kind_schema] = schema

    def get(self, kind: KindObject, kind_schema: KindSchema) -> "BaseSchema":
        schemas = self.schemas
        if (schemas_for_kind := schemas.get(kind)) is None:
            raise ValueError(f"No schemas for kind `{kind.name}`.")
        elif (schema := schemas_for_kind.get(kind_schema)) is None:
            msg = f"No schema of type `{kind_schema}` for `{kind.name}`."
            raise ValueError(msg)
        return schema


registry = Registry()


class BaseSchema(BaseModel):

    model_config = ConfigDict(use_enum_values=False, from_attributes=True)

    # NOT FIELDS SINCE THEY ARE CONSTANT. METADATA FOR CONSUMERS!
    kind_mapped: ClassVar[models.KindObject]
    kind_schema: ClassVar[KindSchema]
    registry: ClassVar[Registry] = registry

    def __init_subclass__(cls) -> None:
        if "Base" in cls.__name__:
            return

        check_enum_opt_attr(cls, "kind_mapped", models.KindObject)
        check_enum_opt_attr(cls, "kind_schema", KindSchema)
        registry.add(cls)


class BaseSearchSchema(BaseSchema):
    kind_mapped: ClassVar[models.KindObject]
    kind_schema: ClassVar[KindSchema]

    uuid: UUIDOptional
    limit: LimitOptional
    name_like: NameLike
    description_like: DescriptionLike
    include_public: Annotated[bool, Field(default=True)]


class BaseUpdateSchema(BaseSchema):
    """This exists because the editor feedback from the decorator feedback was
    not very good at all. Unfortunately all of the fields for update requests
    will have to be explicit.
    """

    kind_mapped: ClassVar[models.KindObject]
    kind_schema: ClassVar[KindSchema]

    @model_validator(mode="after")
    def at_least_one(self) -> Self:

        if not any(getattr(self, field) is not None for field in self.model_fields):
            msg = ", ".join((str(vv) for vv in self.model_fields.values()))
            raise ValueError(f"Must specify at least one of `{msg}`.")
        return self


class BasePrimarySchema(BaseSchema):
    public: bool = True


class BaseSecondarySchema(BaseSchema): ...


class BasePrimaryTableExtraSchema(BaseSchema):

    id: ID
    deleted: Deleted


# --------------------------------------------------------------------------- #


class UserBaseSchema(BasePrimarySchema):
    # _mapped_class = User
    kind_mapped = models.KindObject.user

    name: Name
    description: Description
    url_image: Url
    url: Url


class UserCreateSchema(UserBaseSchema):
    kind_schema = KindSchema.create


class UserUpdateSchema(BaseUpdateSchema):
    kind_mapped = models.KindObject.user
    kind_schema = KindSchema.update

    # NOTE: `url_image` and `url` already optional.
    name: Optional[Name] = None
    description: Optional[Description] = None
    url_image: Url = None
    url: Url = None


class UserSchema(UserBaseSchema):
    kind_schema = KindSchema.default

    uuid: UUID


class UserExtraSchema(BasePrimaryTableExtraSchema, UserSchema):
    kind_schema = KindSchema.extra

    invitation_code: Annotated[
        str | None,
        Field(alias="_prototype_activation_invitation_code"),
    ]
    invitation_email: Annotated[
        str | None,
        Field(alias="_prototype_activation_invitation_email"),
    ]
    invitation_pending: Annotated[
        bool | None,
        Field(alias="_prototype_activation_pending_approval"),
    ]

    @model_validator(mode="after")
    def check_invitation_fields(self) -> Self:

        match (self.invitation_code, self.invitation_email, self.invitation_pending):
            case (str(), str(), bool()):
                return self
            case (None, None, None):
                return self
            case (invitation_code, invitation_pending, invitation_email):
                msg = "The fields `invitation_code`, `invitation_email`, and "
                msg += "`invitation_pending` must all be specified or not."
                msg += "The following combination of values is "
                msg += f"`{invitation_pending=}`, `{invitation_email=}`, and "
                msg += f"`{invitation_code}`."
                raise ValueError(msg)


class UserSearchSchema(BaseSearchSchema):
    kind_mapped = models.KindObject.user
    kind_schema = KindSchema.search


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BasePrimarySchema):
    kind_mapped = models.KindObject.collection

    name: Name
    description: Description


class CollectionCreateSchema(CollectionBaseSchema):
    kind_schema = KindSchema.create


class CollectionUpdateSchema(BaseUpdateSchema):
    kind_mapped = models.KindObject.collection
    kind_schema = KindSchema.update

    uuid_user: Optional[UUID] = None
    name: Optional[Name] = None
    description: Optional[Description] = None


class CollectionMetadataSchema(CollectionBaseSchema):
    kind_schema = KindSchema.metadata
    uuid_user: UUID
    uuid: UUID


class CollectionSchema(CollectionMetadataSchema):
    kind_schema = KindSchema.default


class CollectionExtraSchema(BasePrimaryTableExtraSchema, CollectionSchema):
    kind_schema = KindSchema.extra


class CollectionSearchSchema(BaseSearchSchema):
    kind_schema = KindSchema.search
    kind_mapped = models.KindObject.collection

    uuid_collection: UUIDS


# =========================================================================== #
# Assignments


class AssignmentBaseSchema(BaseSecondarySchema):
    kind_mapped = models.KindObject.assignment


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class AssignmentCreateSchema(AssignmentBaseSchema):
    kind_schema = KindSchema.create


class AssignmentSchema(AssignmentBaseSchema):
    kind_schema = KindSchema.default

    uuid: UUID
    uuid_collection: UUID
    uuid_document: UUID


class AssignmentExtraSchema(AssignmentSchema):
    kind_schema = KindSchema.extra

    deleted: Deleted
    id_collection: ID
    id_document: ID


# =========================================================================== #
# Documents


class DocumentBaseSchema(BasePrimarySchema):
    kind_mapped = models.KindObject.document

    name: Name
    description: Description
    format: Format


class DocumentCreateSchema(DocumentBaseSchema):
    kind_schema = KindSchema.create

    content: Content
    # uuid_collection: UUIDS
    # uuid_user: UUIDS


class DocumentUpdateSchema(BaseUpdateSchema):
    kind_mapped = models.KindObject.document
    kind_schema = KindSchema.update

    name: Optional[Name] = None
    description: Optional[Description] = None
    format: Optional[Format] = None
    content: Optional[Content] = None
    message: Optional[Message] = None

    @field_validator("content", mode="before")
    def check_message_only_when_content(
        cls,
        v: Any,
        info: FieldValidationInfo,
    ) -> Any:
        if v is None:
            return v

        match info.data:
            case object(content=str(), message=str() | None):
                pass
            case object(content=None, message=str()):
                msg = "`message` may only be specified when `content` is."
                raise ValueError(msg)

        return v


class DocumentMetadataSchema(DocumentBaseSchema):
    kind_schema = KindSchema.metadata

    uuid: UUID


class DocumentSchema(DocumentMetadataSchema):
    kind_schema = KindSchema.default

    content: Content
    public: bool = True


class DocumentExtraSchema(BasePrimaryTableExtraSchema, DocumentSchema):
    kind_schema = KindSchema.extra


class DocumentSearchSchema(BaseSearchSchema):
    kind_mapped = models.KindObject.document
    kind_schema = KindSchema.search

    uuid_document: UUIDS


class TimespanLimitParams(BaseModel):

    limit: LimitOptional
    before: UnixTimestampOptional
    after: UnixTimestampOptional

    @computed_field
    @property
    def before_timestamp(self) -> int | None:
        if self.before is None:
            return
        return int(datetime.timestamp(self.before))

    @computed_field
    @property
    def after_timestamp(self) -> int | None:
        if self.after is None:
            return
        return int(datetime.timestamp(self.after))

    @model_validator(mode="after")
    def check_before_after(self) -> Self:
        if self.before is None or self.after is None:
            return self

        if self.before < self.after:
            raise ValueError("`before` must be less than `after`.")

        return self


# =========================================================================== #
# Grants


Pending: TypeAlias = Annotated[bool, Field(description="Grant pending status.")]
PendingFrom: TypeAlias = Annotated[
    models.PendingFrom, Field(description="Grant pending origin.")
]


class GrantBaseSchema(BaseSecondarySchema):
    kind_mapped = models.KindObject.grant

    # NOTE: `uuid_document` is not included here because this is only used in
    #       `POST /grants/users/<uuid>`.
    level: Level

    @field_validator("level", mode="before")
    def validate_level(cls, v) -> None | models.Level:
        match v:
            case int() as level_value:
                return models.Level._value2member_map_.get(level_value)
            case str() as level_name:
                return models.Level[level_name]
            case models.LevelStr() as levelstr:
                return models.Level(levelstr.name)
            case _:
                return v

    @field_serializer("level")
    def enum_as_name(item: enum.Enum):
        return item.name


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class GrantCreateSchema(GrantBaseSchema):
    kind_schema = KindSchema.create


class GrantSchema(GrantBaseSchema):
    kind_schema = KindSchema.default

    # Useful
    uuid: UUID
    uuid_document: UUID
    uuid_user: UUID
    pending: Pending
    pending_from: PendingFrom

    @field_serializer("level", "pending_from")
    def enum_as_name(item: enum.Enum):
        return item.name

    # Metadata
    uuid_parent: Optional[UUID] = None
    uuid_user_granter: Optional[UUID] = None  # should it reeally be optional


class GrantExtraSchema(GrantSchema):
    kind_schema = KindSchema.extra

    deleted: Deleted
    id_document: ID
    id_user: ID
    pending: Pending
    pending_from: PendingFrom

    children: Annotated["List[GrantExtraSchema]", Field()]


# =========================================================================== #
# Edits Schema


class EditBaseSchema(BaseSchema):
    kind_mapped = models.KindObject.edit

    content: Content
    message: Message


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED.
class EditCreateSchema(EditBaseSchema):
    kind_schema = KindSchema.create


class EditMetadataSchema(EditBaseSchema):
    kind_schema = KindSchema.metadata


class EditSchema(EditMetadataSchema):
    kind_schema = KindSchema.default

    uuid_document: UUID


class EditExtraSchema(BasePrimaryTableExtraSchema, EditSchema):
    kind_schema = KindSchema.extra

    id_document: ID


class EditSearchSchema(BaseSearchSchema):
    kind_mapped = models.KindObject.edit
    kind_schema = KindSchema.search


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseSchema):
    kind_mapped = models.KindObject.event

    api_origin: str
    api_version: str
    uuid_parent: UUIDOptional
    uuid: UUID
    uuid_obj: UUID
    uuid_user: UUID
    kind: KindEvent
    kind_obj: KindObject
    timestamp: UnixTimestamp
    detail: Detail

    @computed_field
    @property
    def timestamp_string(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp)  # type: ignore

    @field_serializer("kind_obj", return_type=str)
    def serailize__obj(self, v: Any, info) -> str:
        return v.name

    @field_validator("kind_obj", mode="before")
    def validate_kind(cls, v: None | str | KindObject) -> None | KindObject:
        if isinstance(v, str):
            try:
                w = models.KindObject[v]
            except KeyError:
                w = models.KindObject._value2member_map_.get(v)
                if w is None:
                    msg = f"Could not find enum value associated with `{v}`."
                    raise ValueError(msg)
            return w

        return v


class EventMetadataSchema(EventBaseSchema):
    kind_schema = KindSchema.metadata


class EventSchema(EventMetadataSchema):
    kind_schema = KindSchema.default

    children: Annotated["List[EventSchema]", Field(default=list())]


class EventExtraSchema(EventBaseSchema):
    kind_schema = KindSchema.extra

    data: "AsOutput"
    children: Annotated["List[EventExtraSchema]", Field(default=list())]


class BaseEventParams(BaseModel):
    limit: LimitOptional
    before: UnixTimestampOptional
    after: Annotated[
        datetime,
        Field(validate_default=True, default=None),
        create_validate_datetime(timedelta(days=3)),
    ]

    def _timestamp(self, v: datetime | None) -> int | None:
        return int(datetime.timestamp(v)) if v is not None else None

    @property
    def timestamp_before(self) -> int | None:
        return self._timestamp(self.before)

    @property
    def timestamp_after(self) -> int | None:
        return self._timestamp(self.after)


class EventSearchSchema(BaseEventParams):
    kind_mapped: ClassVar[models.KindObject] = models.KindObject.event
    kind_schema: ClassVar[KindSchema] = KindSchema.search

    # NOTE: It appears that using `Query(None)` as the field default is what
    #       will help fastapi find `uuid_event`. This was tricky to find so do
    #       not touch this. The result was though up on the basis that using
    #       `uuid_event: Set[str] | None = Query(None)` in the endpoint
    #       signature worked.
    uuid_event: Annotated[Set[str] | None, Field(default=Query(None))]

    kind: KindEvent
    kind_obj: KindObject
    uuid_obj: UUID | None = None


class EventParams(BaseEventParams):
    # NOTE: https://docs.pydantic.dev/2.0/usage/types/datetime/
    root: bool = True


# =========================================================================== #
# Composite schemas
#
# NOTE: Some of these might fit into the previous categories.


T_Output = TypeVar(
    "T_Output",
    # User
    UserSchema,
    UserExtraSchema,
    List[UserSchema],
    List[UserExtraSchema],
    # Document
    DocumentSchema,
    DocumentMetadataSchema,
    DocumentExtraSchema,
    List[DocumentMetadataSchema],
    List[DocumentSchema],
    List[DocumentExtraSchema],
    # Collection
    CollectionSchema,
    CollectionMetadataSchema,
    CollectionExtraSchema,
    List[CollectionSchema],
    List[CollectionMetadataSchema],
    List[CollectionExtraSchema],
    # Edit
    EditSchema,
    EditMetadataSchema,
    EditExtraSchema,
    List[EditSchema],
    List[EditMetadataSchema],
    List[EditExtraSchema],
    # Grant
    GrantSchema,
    GrantExtraSchema,
    List[GrantSchema],
    List[GrantExtraSchema],
    # Assignment
    AssignmentSchema,
    AssignmentExtraSchema,
    List[AssignmentSchema],
    List[AssignmentExtraSchema],
    # Event
    EventMetadataSchema,
    EventSchema,
    EventExtraSchema,
    List[EventMetadataSchema],
    List[EventSchema],
    List[EventExtraSchema],
)


# This is the primary response. See https://youtu.be/HBH6qnj0trU?si=7YIqUkPl4gB5S_sP
class AsOutput(BaseModel, Generic[T_Output]):
    # : Annotated[KindObject, BeforeValidator(kind), Field()]
    data: Annotated[T_Output, Field(desciption="Wrapped data.")]

    @computed_field
    @property
    def kind(self) -> models.KindObject | None:
        if (ff := self.first()) is not None:
            return ff.kind_mapped

    @computed_field
    @property
    def kind_schema(self) -> KindSchema | None:
        if (ff := self.first()) is not None:
            return ff.kind_schema
        return None

    @computed_field
    @property
    def kind_nesting(self) -> KindNesting | None:
        match self.data:
            case list():
                return KindNesting.array
            case dict():
                return KindNesting.object
            case _:
                return None

    @computed_field
    @property
    def name_schema(self) -> str:
        return self.first().__class__.__name__

    def first(self) -> Any | None:
        match self.data:
            case [object() as item, *_]:
                return item
            case []:
                return None
            case object() as item:
                return item
            case bad:
                msg = f"Cannot determine `` from malformed data `{bad}`."
                raise ValueError(msg)


# T_OutputEvents = TypeVar(
#     "T_OutputEvents",
#     EventSchema,
#     EventWithObjectsSchema,
# )


class OutputWithEvents(AsOutput, Generic[T_Output]):
    events: Annotated[List[EventSchema], Field()]


T_mwargs = TypeVar("T_mwargs", bound=type(BaseModel))


# Cause I hate wrapping kwargs in dict.
def mwargs(M: Type[T_mwargs], **kwargs) -> T_mwargs:
    return M(**kwargs)


# --------------------------------------------------------------------------- #
# Error Message Schemas.


class ErrBase(BaseModel):
    msg: str


class ErrObjMinSchema(ErrBase):
    uuid_obj: UUID
    kind_obj: KindObject


class ErrAccessUser(ErrBase):
    uuid_user: UUID
    uuid_user_token: UUID


class ErrAccessCollection(ErrBase):
    uuid_user: UUID
    uuid_collection: UUID


class ErrAccessEvent(ErrBase):
    uuid_user: UUID
    uuid_event: UUID


class ErrAccessDocumentGrantNone(ErrBase):
    uuid_document: UUID
    uuid_user: UUID
    level_grant_required: Level


class ErrAccessCannotRejectOwner(ErrBase):
    uuid_user_revoker: UUID
    uuid_document: UUID
    uuid_user_revokees: List[str]


class ErrAccessDocument(ErrAccessDocumentGrantNone):
    level_grant: Level
    uuid_grant: UUID


T_ErrDetail = TypeVar("T_ErrDetail", bound=BaseModel | str)


class ErrDetail(BaseModel, Generic[T_ErrDetail]):
    detail: T_ErrDetail
