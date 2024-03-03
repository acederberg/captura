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
from copy import deepcopy
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
    Tuple,
    Type,
    TypeVar,
    Unpack,
)

from fastapi import Query
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    computed_field,
    create_model,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo
from pydantic_core.core_schema import FieldValidationInfo

from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
    Assignment,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindEvent,
    KindObject,
    KindRecurse,
    Level,
)
from app.models import PendingFrom as PendingFrom_
from app.models import User


# --------------------------------------------------------------------------- #

UUID = Annotated[
    str,
    _FieldUUID := Field(
        min_length=4,
        max_length=16,
        description="Universally unique identifier for a table row.",
    ),
]
UUIDOptional = Annotated[str | None, _FieldUUID]
UnixTimestamp = Annotated[None | int, Field(description="Unix timestamp.")]
Name = Annotated[str, Field(min_length=1, max_length=LENGTH_NAME)]
Description = Annotated[
    str,
    Field(min_length=1, max_length=LENGTH_DESCRIPTION),
]
Url = Annotated[str | None, Field(min_length=8, max_length=LENGTH_URL)]
Content = Annotated[str, Field(max_length=LENGTH_CONTENT)]
Format = Annotated[Literal["md", "rst", "tEx"], Field(default="md")]
Message = Annotated[str, Field(min_length=0, max_length=LENGTH_MESSAGE)]
UUIDS = Annotated[Set[str] | None, Field(default=None)]
ID = Annotated[int, Field()]
Pending = Annotated[bool, Field()]
PendingFrom = Annotated[PendingFrom_, Field()]
Deleted = Annotated[bool, Field()]
Detail = Annotated[str | None, Field(default=None)]


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

class Registry():

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
    kind_mapped: ClassVar[KindObject]
    kind_schema: ClassVar[KindSchema]
    registry: ClassVar[Registry] = registry

    def __init_subclass__(cls) -> None:
        # super().__init_subclass__()
        if "Base" in cls.__name__:
            return

        cls.check_kind("kind_mapped", KindObject)
        cls.check_kind("kind_schema", KindSchema)
        registry.add(cls)

    @classmethod
    def check_kind(cls, field: str, Enum: Type[enum.Enum]) -> None:
        if not hasattr(cls, field):
            msg = f"`{cls.__name__}` missing explicit `{field}`."
            raise AttributeError(msg)

        match getattr(cls, field, None):
            case Enum() | None:
                pass
            case bad:
                raise ValueError(
                    f"`{cls.__name__}` has incorrect type for `{field}`."
                    f"Expected `{Enum}` or `None` (got `{bad}` of type "
                    f"`{type(bad)}`)."
                )



class BaseSearchSchema(BaseSchema):
    kind_mapped: ClassVar[KindObject]
    kind_schema: ClassVar[KindSchema]

    uuid: Annotated[Set[str] | None, Field(default=None)]
    limit: Annotated[int, Field(default=10)]
    name_like: Annotated[str | None, Field(default=None)]
    description_like: Annotated[str | None, Field(default=None)]
    include_public: Annotated[bool, Field(default=True)]


class BaseUpdateSchema(BaseSchema):
    """This exists because the editor feedback from the decorator feedback was
    not very good at all. Unfortunately all of the fields for update requests
    will have to be explicit.
    """

    kind_mapped: ClassVar[KindObject]
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
    kind_mapped = KindObject.user

    name: Name
    description: Description
    url_image: Url
    url: Url


class UserCreateSchema(UserBaseSchema):
    kind_schema = KindSchema.create


class UserUpdateSchema(BaseUpdateSchema):
    kind_mapped = KindObject.user
    kind_schema = KindSchema.update

    # NOTE: `url_image` and `url` already optional.
    name: Optional[Name] = None
    description: Optional[Description] = None
    url_image: Url
    url: Url


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
    kind_mapped = KindObject.user
    kind_schema = KindSchema.search


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BasePrimarySchema):
    kind_mapped = KindObject.collection

    name: Name
    description: Description


class CollectionCreateSchema(CollectionBaseSchema):
    kind_schema = KindSchema.create


class CollectionUpdateSchema(BaseUpdateSchema):
    kind_mapped = KindObject.collection
    kind_schema = KindSchema.update

    uuid_user: UUID
    name: Optional[Name] = None
    description: Optional[Description] = None


class CollectionMetadataSchema(CollectionBaseSchema):
    kind_schema = KindSchema.metadata

    uuid: UUID


class CollectionSchema(CollectionMetadataSchema):
    kind_schema = KindSchema.default

    uuid: UUID


class CollectionExtraSchema(BasePrimaryTableExtraSchema, CollectionSchema):
    kind_schema = KindSchema.extra


class CollectionSearchSchema(BaseSearchSchema):
    kind_schema = KindSchema.search
    kind_mapped = KindObject.collection

    uuid_collection: UUIDS


# =========================================================================== #
# Assignments


class AssignmentBaseSchema(BaseSecondarySchema):
    kind_mapped = KindObject.assignment


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
    kind_mapped = KindObject.document

    name: Name
    description: Description
    format: Format


class DocumentCreateSchema(DocumentBaseSchema):
    kind_schema = KindSchema.create

    content: Content


class DocumentUpdateSchema(BaseUpdateSchema):
    kind_mapped = KindObject.document
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
    kind_mapped = KindObject.document
    kind_schema = KindSchema.search

    uuid_document: UUIDS


# =========================================================================== #
# Grants


class GrantBaseSchema(BaseSecondarySchema):
    kind_mapped = KindObject.grant

    # NOTE: `uuid_document` is not included here because this is only used in
    #       `POST /grants/users/<uuid>`.
    level: Annotated[Level, Field()]

    @field_validator("level", mode="before")
    def validate_level(cls, v) -> None | Level:
        if isinstance(v, int):
            return Level._value2member_map_.get(v)
        elif isinstance(v, str):
            return Level[v]
        else:
            return v


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class GrantCreateSchema(GrantBaseSchema):
    kind_schema = KindSchema.create


class GrantSchema(GrantBaseSchema):
    kind_schema = KindSchema.default

    # Useful
    uuid: UUID
    uuid_document: UUID
    uuid_user: UUID

    # Metadata
    uuid_parent: UUID
    uuid_user_granter: UUID


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
    kind_mapped = KindObject.edit

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
    kind_mapped = KindObject.edit
    kind_schema = KindSchema.search


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseSchema):
    kind_mapped = KindObject.event

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
                w = KindObject[v]
            except KeyError:
                w = KindObject._value2member_map_.get(v)
                if w is None:
                    msg = f"Could not find enum value associated with `{v}`."
                    raise ValueError(msg)
            return w

        return v


# class EventWithRootSchema(EventBaseSchema):
#     kind_schema = KindSchema.metadata
#
#     uuid_root: str


class EventMetadataSchema(EventBaseSchema):
    kind_schema = KindSchema.metadata


class EventSchema(EventMetadataSchema):
    kind_schema = KindSchema.default

    children: Annotated["List[EventSchema]", Field(default=list())]


class EventExtraSchema(EventBaseSchema):
    kind_schema = KindSchema.extra

    data: "AsOutput"
    children: Annotated["List[EventExtraSchema]", Field(default=list())]


# class KindObjectMinimalSchema(enum.Enum):
#     users = UserSchema
#     collections = CollectionMetadataSchema
#     documents = DocumentMetadataSchema
#     events = EventSchema
#     assignments = AssignmentSchema
#     grants = GrantSchema


# class EventActionSchema(BaseModel):
#     event_action: EventSchema
#     event_root: EventSchema


# NOTE: Could use partials but I like this pattern more.
def create_validate_datetime(delta: timedelta) -> BeforeValidator:
    def validator(v: Any, field_info: FieldValidationInfo) -> Any:
        if v:
            return v

        utcnow = datetime.utcnow()
        return utcnow - delta

    return BeforeValidator(validator)


class BaseEventParams(BaseModel):
    limit: Annotated[int | None, Field(default=None)]
    before: Annotated[
        datetime | None,
        Field(default=None),
    ]
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
    kind_mapped: ClassVar[KindObject] = KindObject.event
    kind_schema: ClassVar[KindSchema] = KindSchema.search

    # NOTE: It appears that using `Query(None)` as the field default is what
    #       will help fastapi find `uuid_event`. This was tricky to find so do
    #       not touch this. The result was though up on the basis that using
    #       `uuid_event: Set[str] | None = Query(None)` in the endpoint
    #       signature worked.
    uuid_event: Annotated[Set[str] | None, Field(default=Query(None))]

    kind: Annotated[KindEvent | None, Field(default=None)]
    kind_obj: Annotated[KindObject | None, Field(default=None)]
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
    data: Annotated[T_Output, Field()]

    @computed_field
    @property
    def kind(self) -> KindObject | None:
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
