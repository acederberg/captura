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
from pydantic import (BaseModel, ConfigDict, Field, create_model,
                      field_serializer, field_validator, model_validator)
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


class BaseSearchSchema(BaseModel):
    _mapped_class: ClassVar[Type]

    uuid: Annotated[Set[str] | None, Field(default=None)]
    limit: Annotated[int, Field(default=10)]
    name_like: Annotated[str | None, Field(default=None)]
    description_like: Annotated[str | None, Field(default=None)]
    include_public: Annotated[bool, Field(default=True)]


class BaseSchema(BaseModel):
    _mapped_class: ClassVar[Type]
    model_config = ConfigDict(use_enum_values=False, from_attributes=True,
                              )


class BasePrimarySchema(BaseSchema):
    public: bool = True


class BaseSecondarySchema(BaseSchema):
    ...


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
    _mapped_class = User
    kind: Annotated[Literal[KindObject.user], Field(default=KindObject.user)]

    name: Name
    description: Description
    url_image: Url
    url: Url


class UserCreateSchema(UserBaseSchema):
    ...


@optional
class UserUpdateSchema(UserCreateSchema):
    ...


class UserSchema(UserBaseSchema):
    uuid: UUID


class UserExtraSchema(UserSchema):
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
    _mapped_class = User


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BasePrimarySchema):
    _mapped_class = Collection
    kind: Annotated[
        Literal[KindObject.collection], Field(default=KindObject.collection)
    ]

    name: Name
    description: Description


class CollectionCreateSchema(CollectionBaseSchema):
    ...


@optional
class CollectionUpdateSchema(CollectionCreateSchema):
    uuid_user: UUID


class CollectionMetadataSchema(CollectionBaseSchema):
    uuid: UUID


class CollectionSchema(CollectionMetadataSchema):
    model_config = ConfigDict(from_attributes=True)

    uuid: UUID


class CollectionSearchSchema(BaseSearchSchema):
    _mapped_class = Collection
    uuid_collection: UUIDS


# =========================================================================== #
# Assignments


class AssignmentBaseSchema(BaseSecondarySchema):
    kind: Annotated[
        Literal[KindObject.assignment], Field(default=KindObject.assignment)
    ]
    _mapped_class = Assignment


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED. MOST FIELDS NOT UPDATABLE
class AssignmentCreateSchema(AssignmentBaseSchema):
    ...


class AssignmentSchema(AssignmentBaseSchema):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID
    deleted: bool


# =========================================================================== #
# Documents


class DocumentBaseSchema(BasePrimarySchema):
    # uuid was initially excluded bc metadata is labeld by it.
    # But returning dictionaries sucks so it will be removed soon.
    kind: Annotated[Literal[KindObject.document], Field(default=KindObject.document)]
    _mapped_class = Document

    name: Name
    description: Description
    format: Format


class DocumentCreateSchema(DocumentBaseSchema):
    content: Content


@optional
class DocumentUpdateSchema(DocumentCreateSchema):
    ...


class DocumentMetadataSchema(DocumentUpdateSchema):
    uuid: UUID


class DocumentSchema(DocumentMetadataSchema):
    # name: Name
    content: Content
    public: bool = True


class DocumentSearchSchema(BaseSearchSchema):
    _mapped_class = Document
    uuid_document: UUIDS


# =========================================================================== #
# Grants


class GrantBaseSchema(BaseSecondarySchema):
    _mapped_class = Grant
    kind: Annotated[Literal[KindObject.grant], Field(default=KindObject.grant)]

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
    ...


class GrantSchema(GrantBaseSchema):
    model_config = ConfigDict(from_attributes=True)
    uuid: UUID
    uuid_document: UUID


# =========================================================================== #
# Edits Schema


class EditBaseSchema(BaseSchema):
    kind: Annotated[Literal[KindObject.edit], Field(default=KindObject.edit)]
    _mapped_class = Edit

    content: Content
    message: Message


# NOTE: NO UPDATE SCHEMA! UPDATING IS NOT ALLOWED.
class EditCreateSchema(EditBaseSchema):
    ...


class EditMetadataSchema(EditBaseSchema):
    ...


class EditSchema(EditMetadataSchema):
    ...


class EditSearchSchema(BaseSearchSchema):
    _mapped_class = Edit


# =========================================================================== #
# Events Schema


class EventBaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    _mapped_class = Event

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
#     kind: KindObject
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
    UserSchema,
    UserExtraSchema,
    DocumentSchema,
    CollectionSchema,
    EditSchema,
    GrantSchema,
    AssignmentSchema,
    List[UserSchema],
    List[UserExtraSchema],
    List[DocumentSchema],
    List[CollectionSchema],
    List[EditSchema],
    List[GrantSchema],
    List[AssignmentSchema],
)


def kind(v: Any, field_info: FieldValidationInfo) -> KindObject:
    if v:
        raise ValueError("Cannot set `kind` explicitly.")

    match field_info.data:
        case {"data": list()}:
            kind = KindObject.bulk
        case {"data": {"kind": kind}}:
            kind = kind
        case _:
            msg = "Cannot determine `kind` from malformed data."
            raise ValueError(msg)

    return kind


# This is the primary response. See https://youtu.be/HBH6qnj0trU?si=7YIqUkPl4gB5S_sP
class AsData(BaseModel, Generic[T_Spec]):
    data: Annotated[T_Spec, Field()]
    kind: Annotated[KindObject, Field()]


class WithEvents(AsData, Generic[T_Spec]):
    events: Annotated[List[EventSchema], Field()]
