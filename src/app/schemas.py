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
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
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
Content = Annotated[str, Field(max_length=LENGTH_CONTENT)]
Format = Annotated[str, Field(min_length=64, max_length=LENGTH_CONTENT)]
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


class CollectionMetadataSchema(BaseModel):
    uuid: UUID
    # name: Name # excluded bc metadata is labeled by name
    description: Description


class CollectionSchema(BaseModel):
    uuid: UUID
    name: Name
    description: Description


class DocumentMetadataSchema(BaseModel):
    uuid: UUID
    # name: Name
    description: Description


class DocumentSchema(DocumentMetadataSchema):
    name: Name
    content: Content
    content_fmt: Format


class EditMetadataSchema(BaseModel):
    uuid: UUID


class EditSchema(BaseModel):
    content: Content
    message: Message
