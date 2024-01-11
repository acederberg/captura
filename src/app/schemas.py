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
from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
    KindEvent,
    Level,
    KindObject,
)

UUID = Annotated[
    None | str,
    Field(
        min_length=4,
        max_length=16,
        description="Universally unique identifier for a table row.",
    ),
]
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


def generate_alias(v: str) -> str:
    if v.startswith("_"):
        v = v.replace("_", "", 1)
    return v


class BaseSchema(BaseModel):
    model_config = ConfigDict(alias_generator=generate_alias)
    updated_timestamp: UnixTimestamp
    created_timestamp: UnixTimestamp
    updated_by_user_uuid: UUID
    created_by_user_uuid: UUID


# =========================================================================== #
# User schemas


class UserUpdateSchema(BaseModel):
    public: bool | None = None
    name: Name | None = None
    description: Description | None = None
    url_image: Url = None
    url: Url = None


class UserSchema(BaseModel):
    uuid: UUID = None
    name: Name
    description: Description
    url_image: Url = None
    url: Url = None


# =========================================================================== #
# Collection and Assignment Schema


class CollectionBaseSchema(BaseModel):
    name: Name
    description: Description


class CollectionPostSchema(CollectionBaseSchema):
    public: bool = True


class CollectionPatchSchema(BaseModel):
    name: Name | None = None
    description: Description | None = None
    uuid_user: UUID = None
    public: bool | None = None


class CollectionMetadataSchema(CollectionBaseSchema):
    uuid: UUID = None
    uuid_user: UUID = None


class CollectionSchema(CollectionPostSchema):
    uuid: UUID


class AssignmentPostSchema(BaseModel):
    uuid_document: UUID
    uuid_collection: UUID


class AssignmentSchema(AssignmentPostSchema):
    uuid: UUID


# =========================================================================== #
# Docoment and Grant Schemas


class DocumentMetadataSchema(BaseModel):
    uuid: UUID = None
    name: Name  # excluded bc metadata is labeld by name.
    description: Description
    format: Format


class DocumentSchema(DocumentMetadataSchema):
    # name: Name
    content: Content
    public: bool = True


class DocumentPostSchema(BaseModel):
    public: bool = True


class GrantPostSchema(BaseModel):
    # NOTE: `uuid_document` is not included here because this is only used in
    #       `POST /grants/users/<uuid>`.
    model_config = ConfigDict(use_enum_values=False)
    uuid_user: UUID
    level: Annotated[Level, Field()]

    @field_validator("level", mode="before")
    def validate_level(cls, v) -> None | Level:
        if isinstance(v, int):
            return Level._value2member_map_.get(v)
        elif isinstance(v, str):
            return Level[v]
        else:
            return v


class GrantSchema(GrantPostSchema):
    uuid: UUID
    uuid_document: UUID


# =========================================================================== #
# Edits Schema


class EditMetadataSchema(BaseModel):
    uuid: UUID = None


class EditSchema(BaseModel):
    content: Content
    message: Message


class EventSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    api_origin: str
    api_version: str
    uuid_parent: UUID
    uuid: UUID
    uuid_obj: UUID
    uuid_user: UUID
    kind: KindEvent
    kind_obj: KindObject
    timestamp: UnixTimestamp
    detail: str
    children: Annotated["List[EventSchema]", Field(default=list())]


# =========================================================================== #
# Composite schemas
#
# NOTE: Some of these might fit into the previous categories.


class PostUserSchema(UserSchema):
    collections: Annotated[List[CollectionPostSchema], Field(default=list())]
    documents: Annotated[List[DocumentSchema], Field(default=list())]
