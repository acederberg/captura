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
from typing import (Annotated, Any, ClassVar, Generic, List, Literal, Optional,
                    Self, Set, Tuple, Type, TypeVar)

from fastapi import Query
from pydantic import (BaseModel, BeforeValidator, ConfigDict, Field,
                      computed_field, create_model, field_serializer,
                      field_validator, model_validator)
from pydantic.fields import FieldInfo
from pydantic_core.core_schema import FieldValidationInfo

from app.models import (LENGTH_CONTENT, LENGTH_DESCRIPTION, LENGTH_MESSAGE,
                        LENGTH_NAME, LENGTH_URL, Assignment, Collection,
                        Document, Edit, Event, Grant, KindEvent, KindObject,
                        KindRecurse, Level, User)

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
Content = Annotated[bytes, Field(max_length=LENGTH_CONTENT)]
Format = Annotated[Literal["md", "rst", "tEx"], Field(default="md")]
Message = Annotated[str, Field(min_length=0, max_length=LENGTH_MESSAGE)]
UUIDS = Annotated[Set[str] | None, Field(default=None)]


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



class BaseSchema(BaseModel):

    model_config = ConfigDict(use_enum_values=False, from_attributes=True)

    # NOT FIELDS SINCE THEY ARE CONSTANT. METADATA FOR CONSUMERS!
    kind_mapped: ClassVar[KindObject]
    kind_schema: ClassVar[KindSchema]




class BaseSearchSchema(BaseSchema):
    kind_mapped: ClassVar[KindObject]
    kind_schema: ClassVar[KindSchema]

    uuid: Annotated[Set[str] | None, Field(default=None)]
    limit: Annotated[int, Field(default=10)]
    name_like: Annotated[str | None, Field(default=None)]
    description_like: Annotated[str | None, Field(default=None)]
    include_public: Annotated[bool, Field(default=True)]



class BasePrimarySchema(BaseSchema):
    public: bool = True


class BaseSecondarySchema(BaseSchema): ...


def optional(model: Type[BaseModel]) -> Type[BaseModel]:
    def make_field_optional(
        field: FieldInfo,
        default: Any = None,
    ) -> Tuple[Any, FieldInfo]:
        new = deepcopy(field)
        new.default = default
        new.annotation = Optional[field.annotation]  # type: ignore
        return new.annotation, new

    return create_model(
        model.__name__,
        __base__=model,
        __module__=model.__module__,
        # __cls_kwargs__={
        #     field_name: make_field_optional(field_info)
        #     for field_name, field_info in model.model_fields.items()
        # },
    )


# =========================================================================== #
# User schemas


class UserBaseSchema(BasePrimarySchema):
    # _mapped_class = User
    kind_mapped = KindObject.user
    # : Annotated[  
    #     Literal[KindObject.user],
    #     Field(default=KindObject.user),
    # ]

    name: Name
    description: Description
    url_image: Url
    url: Url


class UserCreateSchema(UserBaseSchema):
    # _schema: Annotated[  # type: ignore[reportGeneralTypeErrors]
    #     Literal[KindSchema.create],
    #     Field(default=KindSchema.create),
    # ]
    kind_schema = KindSchema.create


@optional
class UserUpdateSchema(UserCreateSchema):
    # _schema: Annotated[  # type: ignore[reportGeneralTypeErrors]
    #     Literal[KindSchema.update],
    #     Field(default=KindSchema.update),
    # ]
    kind_schema = KindSchema.update


class UserSchema(UserBaseSchema):
    # _schema: Annotated[  # type: ignore[reportGeneralTypeErrors]
    #     Literal[KindSchema.default],
    #     Field(default=KindSchema.default),
    # ]
    kind_schema = KindSchema.default
    uuid: UUID


class UserExtraSchema(UserSchema):
    _schema = KindSchema.extra
    # kind_schema: Annotated[  # type: ignore[reportGeneralTypeErrors]
    #     Literal[KindSchema.extra],
    #     Field(default=KindSchema.extra),
    # ]

    id: int
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
    # _mapped_class = Collection
    kind_mapped = KindObject.collection

    name: Name
    description: Description


class CollectionCreateSchema(CollectionBaseSchema): 
    kind_schema = KindSchema.create


@optional
class CollectionUpdateSchema(CollectionCreateSchema):
    kind_schema = KindSchema.update

    uuid_user: UUID


class CollectionMetadataSchema(CollectionBaseSchema):
    kind_schema = KindSchema.metadata
    
    uuid: UUID


class CollectionSchema(CollectionMetadataSchema):
    kind_schema = KindSchema.default

    uuid: UUID


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
    deleted: bool


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


@optional
class DocumentUpdateSchema(DocumentCreateSchema): 
    kind_schema = KindSchema.update


class DocumentMetadataSchema(DocumentUpdateSchema):
    kind_schema = KindSchema.metadata
    uuid: UUID


class DocumentSchema(DocumentMetadataSchema):
    kind_schema = KindSchema.default

    content: Content
    public: bool = True


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
    # uuid_user: UUID
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

    model_config = ConfigDict(from_attributes=True)
    uuid: UUID
    uuid_document: UUID


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


class EditSearchSchema(BaseSearchSchema):
    kind_mapped = KindObject.edit
    kind_schema = KindSchema.search


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseSchema):
    # kind_mapped: ClassVar[KindObject] = KindObject.event

    api_origin: str
    api_version: str
    uuid_parent: UUIDOptional
    uuid: UUID
    uuid_obj: UUID
    uuid_user: UUID
    kind: KindEvent
    kind_obj: KindObject
    timestamp: UnixTimestamp
    detail: str

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


class EventSearchSchema(BaseSearchSchema):
    kind_mapped = KindObject.event
    kind_schema = KindSchema.search 
    
    uuid_event: UUIDS
    kind: KindEvent | None = None
    _obj: KindObject | None = None
    uuid_obj: str | None = None


class EventWithRootSchema(EventBaseSchema):
    kind_schema = KindSchema.metadata

    uuid_root: str


class EventSchema(EventBaseSchema):
    kind_schema = KindSchema.default

    children: Annotated["List[EventSchema]", Field(default=list())]


class KindObjectMinimalSchema(enum.Enum):
    users = UserSchema
    collections = CollectionMetadataSchema
    documents = DocumentMetadataSchema
    events = EventSchema
    assignments = AssignmentSchema
    grants = GrantSchema


# AnyMinimalSchema = (
#     EventSchema
#     | UserSchema
#     | DocumentMetadataSchema
#     | CollectionMetadataSchema
#     | AssignmentSchema
#     | GrantSchema
# )
#
#
# class ObjectSchema(BaseModel):
#     : KindObject
#     data: AnyMinimalSchema
#


class EventActionSchema(BaseModel):
    event_action: EventSchema
    event_root: EventSchema


# =========================================================================== #
# Composite schemas
#
# NOTE: Some of these might fit into the previous categories.


T_Spec = TypeVar(
    "T_Spec",
    # User
    UserSchema,
    UserExtraSchema,
    List[UserSchema],
    List[UserExtraSchema],

    # Document
    DocumentSchema,
    DocumentMetadataSchema,
    List[DocumentMetadataSchema],
    List[DocumentSchema],

    # Collection
    CollectionSchema,
    CollectionMetadataSchema,
    List[CollectionSchema],
    List[CollectionMetadataSchema],

    # Edit
    EditSchema,
    EditMetadataSchema,
    List[EditSchema],
    List[EditMetadataSchema],

    # Grant
    GrantSchema,
    List[GrantSchema],

    # Assignment
    AssignmentSchema,
    List[AssignmentSchema]
)


# This is the primary response. See https://youtu.be/HBH6qnj0trU?si=7YIqUkPl4gB5S_sP
class AsOutput(BaseModel, Generic[T_Spec]):
    # : Annotated[KindObject, BeforeValidator(kind), Field()]
    data: Annotated[T_Spec, Field()]

    @computed_field
    @property
    def kind(self) -> KindObject:
        return self.first().kind_mapped

    @computed_field
    @property
    def kind_schema(self) -> KindSchema:
        return self.first().kind_schema

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


    def first(self):
        match self.data:
            case [object() as item, *_]:
                return item 
            case object() as item:
                return item
            case bad:
                msg = f"Cannot determine `` from malformed data `{bad}`."
                raise ValueError(msg)




class OutputWithEvents(AsOutput, Generic[T_Spec]):
    events: Annotated[List[EventSchema], Field()]


T_mwargs = TypeVar("T_mwargs", bound=type(BaseModel))


# Cause I hate wrapping kwargs in dict.
def mwargs(M: Type[T_mwargs], **kwargs) -> T_mwargs:
    return M(**kwargs)
