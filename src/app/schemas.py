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
from typing import Annotated, Any, List, Literal, Optional, Self, Set, Tuple, Type

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    create_model,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo

from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
    KindEvent,
    KindObject,
    KindRecurse,
    Level,
)

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


class BaseSearchSchema(BaseModel):
    name_like: Annotated[str | None, Field(default=None)]
    description_like: Annotated[str | None, Field(default=None)]
    limit: Annotated[int, Field(default=10)]
    all_: Annotated[bool, Field(default=True)]


class BaseSchema(BaseModel):
    model_config = ConfigDict(use_enum_values=False, from_attributes=True)


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
    name: Name
    description: Description
    url_image: Url
    url: Url


class UserCreateSchema(UserBaseSchema): ...


@optional
class UserUpdateSchema(UserCreateSchema): ...


class UserSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID = None
    name: Name
    description: Description
    url_image: Url = None
    url: Url = None


class UserSearchSchema(BaseSearchSchema):
    uuid_user: UUIDS


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BasePrimarySchema):
    name: Name
    description: Description


class CollectionCreateSchema(CollectionBaseSchema): ...


@optional
class CollectionUpdateSchema(CollectionCreateSchema):
    uuid_user: UUID


class CollectionMetadataSchema(CollectionBaseSchema):
    uuid: UUID


class CollectionSchema(CollectionUpdateSchema):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID


class CollectionSearchSchema(BaseSearchSchema):
    uuid_collection: UUIDS


# =========================================================================== #
# Assignments


class AssignmentBaseSchema(BaseSecondarySchema): ...


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class AssignmentCreateSchema(AssignmentBaseSchema): ...


class AssignmentSchema(AssignmentBaseSchema):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID
    deleted: bool


# =========================================================================== #
# Documents


class DocumentBaseSchema(BasePrimarySchema):
    # uuid was initially excluded bc metadata is labeld by it.
    # But returning dictionaries sucks so it will be removed soon.
    model_config = ConfigDict(from_attributes=True)

    name: Name
    description: Description
    format: Format


class DocumentCreateSchema(DocumentBaseSchema):
    content: Content


@optional
class DocumentUpdateSchema(DocumentCreateSchema): ...


class DocumentMetadataSchema(DocumentUpdateSchema):
    uuid: UUID


class DocumentSchema(DocumentMetadataSchema):
    # name: Name
    content: Content
    public: bool = True


class DocumentSearchSchema(BaseSearchSchema):
    uuid_document: UUIDS


# =========================================================================== #
# Grants


class GrantBaseSchema(BaseSecondarySchema):
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
class GrantCreateSchema(GrantBaseSchema): ...


class GrantSchema(GrantBaseSchema):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID
    uuid_document: UUID


# =========================================================================== #
# Edits Schema


class EditBaseSchema(BaseSchema):
    content: Content
    message: Message


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED.
class EditCreateSchema(EditBaseSchema): ...


class EditMetadataSchema(EditBaseSchema): ...


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
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
    def serailize_kind_obj(self, v: Any, info) -> str:
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


class EventSearchSchema(BaseModel):
    uuid_event: UUIDS
    kind: KindEvent | None = None
    kind_obj: KindObject | None = None
    uuid_obj: str | None = None


class EventWithRootSchema(EventBaseSchema):
    uuid_root: str


class EventSchema(EventBaseSchema):
    children: Annotated["List[EventSchema]", Field(default=list())]


class KindObjectMinimalSchema(enum.Enum):
    users = UserSchema
    collections = CollectionMetadataSchema
    documents = DocumentMetadataSchema
    events = EventSchema
    assignments = AssignmentSchema
    grants = GrantSchema


AnyMinimalSchema = (
    EventSchema
    | UserSchema
    | DocumentMetadataSchema
    | CollectionMetadataSchema
    | AssignmentSchema
    | GrantSchema
)


class ObjectSchema(BaseModel):
    kind: KindObject
    data: AnyMinimalSchema


class EventActionSchema(BaseModel):
    event_action: EventSchema
    event_root: EventSchema


# =========================================================================== #
# Composite schemas
#
# NOTE: Some of these might fit into the previous categories.


class PostUserSchema(UserSchema):
    collections: Annotated[List[CollectionCreateSchema], Field(default=list())]
    documents: Annotated[List[DocumentSchema], Field(default=list())]
