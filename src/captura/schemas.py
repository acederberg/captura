"""Note: None of these schemas should include ``id`` fields. Instead they
should return err.UUID fields. This is done because, by design, the err.UUIDS of
objects must known if they are to be got. Take for instance the following flow:

1. The ``GET /user`` endpoint gets a users err.UUID from their JWT. The uuid is
    sent in the response.
2. The ``GET /user/collections`` endpoint returns the collections for the user
   returned from the above request.
3. The ``GET /collections/<collection_id>/documents`` endpoint can be used to
   get some err.UUIDs to make queries to the document collection.

From a mathmatical standpoint, this is 'good enough' because err.UUIDs should map
uniquely to a corresponding database row (further, for tables with multiple
foreign keys it is not necessary to specify multiple values).
"""

# =========================================================================== #
import enum
from datetime import datetime, timedelta
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Self,
    Set,
    Type,
    TypeVar,
)

from fastapi import Query
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core.core_schema import FieldValidationInfo
from rich.align import Align, AlignMethod, VerticalAlignMethod
from rich.json import JSON
from rich.panel import Panel

# --------------------------------------------------------------------------- #
from captura import fields
from captura.util import check_enum_opt_attr


# NOTE: Could use partials but I like this pattern more.
def create_validate_datetime(delta: timedelta) -> BeforeValidator:
    def validator(v: Any, field_info: FieldValidationInfo) -> Any:
        if v:
            return v

        utcnow = datetime.now()
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
    schemas: Dict[fields.FieldKindObject, Dict[KindSchema, Type["BaseSchema"]]]

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

    def get(
        self,
        kind: fields.KindObject,
        kind_schema: KindSchema,
    ) -> "Type[BaseSchema]":
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
    kind_mapped: ClassVar[fields.FieldKindObject]
    kind_schema: ClassVar[KindSchema]
    registry: ClassVar[Registry] = registry
    registry_exclude: ClassVar[bool] = False

    def __init_subclass__(cls) -> None:
        if "Base" in cls.__name__:
            return

        if not cls.registry_exclude:
            check_enum_opt_attr(
                cls,
                "kind_mapped",
                fields.KindObject,
            )
            check_enum_opt_attr(cls, "kind_schema", KindSchema)
            registry.add(cls)

    def __rich__(self) -> Panel:
        return self.render()

    def render(
        self,
        align: AlignMethod = "center",
        vertical: VerticalAlignMethod = "middle",
        **kwargs,
    ) -> Panel:
        jj = JSON(self.model_dump_json(**kwargs))
        return Panel(Align(jj, align, vertical=vertical))


class BaseSearchSchema(BaseSchema):
    kind_mapped: ClassVar[fields.FieldKindObject]
    kind_schema: ClassVar[KindSchema]

    # NOTE: It appears that using `Query(None)` as the field default is what
    #       will help fastapi find `uuid_event`. This was tricky to find so do
    #       not touch this. The result was though up on the basis that using
    #       `uuid_event: Set[str] | None = Query(None)` in the endpoint
    #       signature worked.
    uuids: Annotated[Set[str] | None, Field(default=Query(None))]
    limit: fields.FieldLimitOptional
    name_like: fields.FieldNameLike
    description_like: fields.FieldDescriptionLike
    include_public: Annotated[bool, Field(default=True)]
    randomize: Annotated[bool, Field(default=False)]


class BaseUpdateSchema(BaseSchema):
    """This exists because the editor feedback from the decorator feedback was
    not very good at all. Unfortunately all of the fields for update requests
    will have to be explicit.
    """

    kind_mapped: ClassVar[fields.FieldKindObject]
    kind_schema: ClassVar[KindSchema]

    @model_validator(mode="after")
    def at_least_one(self) -> Self:
        if not any(getattr(self, field) is not None for field in self.model_fields):
            msg = ", ".join((str(vv) for vv in self.model_fields.keys()))
            raise ValueError(f"Must specify at least one of `{msg}`.")
        return self


class BasePrimarySchema(BaseSchema):
    public: bool = True


class BaseSecondarySchema(BaseSchema): ...


class BasePrimaryTableExtraSchema(BaseSchema):
    id: fields.FieldID
    deleted: fields.FieldDeleted


# --------------------------------------------------------------------------- #


class UserBaseSchema(BasePrimarySchema):
    # _mapped_class = User
    kind_mapped = fields.KindObject.user

    email: fields.FieldEmail
    name: fields.FieldName
    description: fields.FieldDescription
    url_image: fields.FieldUrl
    url: fields.FieldUrl


class UserCreateSchema(UserBaseSchema):
    kind_schema = KindSchema.create

    content: fields.FieldContent


class UserUpdateSchema(BaseUpdateSchema):
    kind_mapped = fields.KindObject.user
    kind_schema = KindSchema.update

    # NOTE: `url_image` and `url` already optional.
    name: Optional[fields.FieldName] = None
    description: Optional[fields.FieldDescription] = None
    url_image: fields.FieldUrl = None
    url: fields.FieldUrl = None

    content: fields.FieldContent


class UserSchema(UserBaseSchema):
    kind_schema = KindSchema.default

    uuid: fields.FieldUUID

    content: fields.FieldContent


class UserExtraSchema(BasePrimaryTableExtraSchema, UserSchema):
    kind_schema = KindSchema.extra

    deleted: fields.FieldDeleted


class UserSearchSchema(BaseSearchSchema):
    kind_mapped = fields.KindObject.user
    kind_schema = KindSchema.search


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BasePrimarySchema):
    kind_mapped = fields.KindObject.collection

    name: fields.FieldName
    description: fields.FieldDescription


class CollectionCreateSchema(CollectionBaseSchema):
    kind_schema = KindSchema.create

    content: fields.FieldContent


class CollectionUpdateSchema(BaseUpdateSchema):
    kind_mapped = fields.KindObject.collection
    kind_schema = KindSchema.update

    uuid_user: Optional[fields.FieldUUID] = None
    name: Optional[fields.FieldName] = None
    description: Optional[fields.FieldDescription] = None

    content: fields.FieldContent


class CollectionMetadataSchema(CollectionBaseSchema):
    kind_schema = KindSchema.metadata
    uuid_user: fields.FieldUUID
    uuid: fields.FieldUUID


class CollectionSchema(CollectionMetadataSchema):
    kind_schema = KindSchema.default

    content: fields.FieldContent


class CollectionExtraSchema(BasePrimaryTableExtraSchema, CollectionSchema):
    kind_schema = KindSchema.extra


class CollectionSearchSchema(BaseSearchSchema):
    kind_schema = KindSchema.search
    kind_mapped = fields.KindObject.collection


# =========================================================================== #
# Assignments


class AssignmentBaseSchema(BaseSecondarySchema):
    kind_mapped = fields.KindObject.assignment


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class AssignmentCreateSchema(AssignmentBaseSchema):
    kind_schema = KindSchema.create


class AssignmentSchema(AssignmentBaseSchema):
    kind_schema = KindSchema.default

    uuid: fields.FieldUUID
    uuid_collection: fields.FieldUUID
    uuid_document: fields.FieldUUID


class AssignmentExtraSchema(AssignmentSchema):
    kind_schema = KindSchema.extra

    deleted: fields.FieldDeleted
    id_collection: fields.FieldID
    id_document: fields.FieldID


# =========================================================================== #
# Documents


class DocumentBaseSchema(BasePrimarySchema):
    kind_mapped = fields.KindObject.document

    name: fields.FieldName
    description: fields.FieldDescription


class DocumentCreateSchema(DocumentBaseSchema):
    kind_schema = KindSchema.create

    content: fields.FieldContent = None


class DocumentUpdateSchema(BaseUpdateSchema):
    kind_mapped = fields.KindObject.document
    kind_schema = KindSchema.update

    name: Optional[fields.FieldName] = None
    description: Optional[fields.FieldDescription] = None

    content: fields.FieldContent = None


class DocumentMetadataSchema(DocumentBaseSchema):
    kind_schema = KindSchema.metadata

    uuid: fields.FieldUUID


class DocumentSchema(DocumentMetadataSchema):
    kind_schema = KindSchema.default

    content: fields.FieldContent


class DocumentExtraSchema(BasePrimaryTableExtraSchema, DocumentSchema):
    kind_schema = KindSchema.extra


class DocumentSearchSchema(BaseSearchSchema):
    kind_mapped = fields.KindObject.document
    kind_schema = KindSchema.search


class TimespanLimitParams(BaseModel):
    limit: fields.FieldLimitOptional
    before: fields.FieldUnixTimestampOptional
    after: fields.FieldUnixTimestampOptional

    # noqa: prop-decorator
    @property
    def before_timestamp(self) -> int | None:
        if self.before is None:
            return None
        return int(datetime.timestamp(self.before))

    # noqa: prop-decorator
    @property
    def after_timestamp(self) -> int | None:
        if self.after is None:
            return None
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


class GrantBaseSchema(BaseSecondarySchema):
    kind_mapped = fields.KindObject.grant

    # NOTE: `uuid_document` is not included here because this is only used in
    #       `POST /grants/users/<uuid>`.
    level: fields.FieldLevel

    @field_serializer("level")
    def enum_as_name(item: enum.Enum):  # type: ignore
        return item.name


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class GrantCreateSchema(GrantBaseSchema):
    kind_schema = KindSchema.create


class GrantSchema(GrantBaseSchema):
    kind_schema = KindSchema.default

    # Useful
    uuid: fields.FieldUUID
    uuid_document: fields.FieldUUID
    uuid_user: fields.FieldUUID
    pending: fields.FieldPending
    pending_from: fields.FieldPendingFrom

    @field_serializer("level", "pending_from")
    def enum_as_name(item: enum.Enum):  # type: ignore
        return item.name

    # Metadata
    uuid_parent: Optional[fields.FieldUUID] = None
    uuid_user_granter: Optional[fields.FieldUUID] = (
        None  # should it reeally be optional
    )


class GrantExtraSchema(GrantSchema):
    kind_schema = KindSchema.extra

    deleted: fields.FieldDeleted
    id_document: fields.FieldID
    id_user: fields.FieldID
    pending: fields.FieldPending
    pending_from: fields.FieldPendingFrom

    children: Annotated["List[GrantExtraSchema]", Field()]


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseSchema):
    kind_mapped = fields.KindObject.event

    api_origin: str
    api_version: str
    uuid_parent: fields.FieldUUIDOptional
    uuid: fields.FieldUUID
    uuid_obj: fields.FieldUUID
    uuid_user: fields.FieldUUID
    kind: fields.FieldKindEvent
    kind_obj: fields.FieldKindObject
    timestamp: fields.FieldUnixTimestamp
    detail: fields.FieldDetail

    # noqa: prop-decorator
    @property
    def timestamp_string(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp)  # type: ignore

    @field_serializer("kind_obj", return_type=str)
    def serailize__obj(self, v: Any, info) -> str:
        return v.name

    @field_validator("kind_obj", mode="before")
    def validate_kind(
        cls, v: None | str | fields.FieldKindObject
    ) -> None | fields.FieldKindObject:
        if isinstance(v, str):
            try:
                w = fields.KindObject[v]
            except KeyError:
                w = fields.KindObject._value2member_map_.get(v)  # type: ignore
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
    limit: fields.FieldLimitOptional
    before: fields.FieldUnixTimestampOptional
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
    kind_mapped: ClassVar[fields.FieldKindObject] = fields.KindObject.event
    kind_schema: ClassVar[KindSchema] = KindSchema.search

    # NOTE: It appears that using `Query(None)` as the field default is what
    #       will help fastapi find `uuid_event`. This was tricky to find so do
    #       not touch this. The result was though up on the basis that using
    #       `uuid_event: Set[str] | None = Query(None)` in the endpoint
    #       signature worked.
    uuid_event: Annotated[Set[str] | None, Field(default=Query(None))]

    kind: fields.FieldKindEvent
    kind_obj: fields.FieldKindObject
    uuid_obj: fields.FieldUUID | None = None


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
    # : Annotated[fields.FieldKindObject, BeforeValidator(kind), Field()]
    data: Annotated[T_Output, Field(desciption="Wrapped data.")]

    # noqa: prop-decorator
    @property
    def kind(self) -> fields.FieldKindObject | None:
        if (ff := self.first()) is not None:
            return ff.kind_mapped
        return None

    # noqa: prop-decorator
    @property
    def kind_schema(self) -> KindSchema | None:
        if (ff := self.first()) is not None:
            return ff.kind_schema
        return None

    # noqa: prop-decorator
    @property
    def kind_nesting(self) -> KindNesting | None:
        match self.data:
            case list():
                return KindNesting.array
            case dict():
                return KindNesting.object
            case _:
                return None

    # noqa: prop-decorator
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


# --------------------------------------------------------------------------- #


class TMwargs(Protocol):
    # NOTE: Adding a signature for init with ``kwargs`` is a pain.
    ...


T_mwargs = TypeVar("T_mwargs", bound=BaseModel | TMwargs)


# NOTE: Cause I hate wrapping kwargs in dict and pydantic constructor hints are
#       often annoying. This can be applied anything with a kwargs constructor.
def mwargs(M: Type[T_mwargs], **kwargs) -> T_mwargs:
    return M(**kwargs)  # type: ignore
