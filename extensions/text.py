# =========================================================================== #
import enum
from typing import Annotated, List

from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, TypeAdapter, Field

# --------------------------------------------------------------------------- #
from app import fields
from app.controllers.base import Data, ResolvedDocument
from app.depends import DependsAccess, DependsRead
from app.schemas import AsOutput, EditSchema, TimespanLimitParams, mwargs
from app.views import BaseView, args

# --------------------------------------------------------------------------- #
# Fields

LENGTH_MESSAGE: int = 1024
LENGTH_CONTENT: int = 2**15
LENGTH_FORMAT: int = 8


class Format(str, enum.Enum):
    md = "md"
    rst = "rst"
    tEx = "tEx"
    txt = "txt"
    docs = "docs"


FieldFormat = Annotated[
    Format,
    Field(default=Format.md, description="Text document format."),
]


FieldMessage = Annotated[
    str,
    Field(
        min_length=0,
        max_length=LENGTH_MESSAGE,
        description="Text document edit message.",
        examples=["The following changes were made to the document: ..."],
    ),
]

FieldContent = Annotated[
    str,
    Field(
        max_length=LENGTH_CONTENT,
        description="Text document content.",
        examples=[fields.EXAMPLE_CONTENT],
    ),
]
FieldTags = Annotated[
    List[str] | None,
    Field(
        max_length=8,
        description="Text document tags.",
    ),
]

# --------------------------------------------------------------------------- #


class TextSchema(BaseModel):
    """How the content schema should look."""

    format: FieldFormat
    content: FieldContent
    tags: FieldTags


class TextView(BaseView):
    """ """

    view_routes = dict(
        get_content=dict(
            url="/content",
            name="Get Raw Document Content",
        ),
        get_rendered=dict(
            url="/rendered",
            name="Get Rendered Document Content",
        ),
        get_recent_document_edits=dict(
            url="/edits",
            name="Get Document Edits",
        ),
    )

    @classmethod
    def patch_text_document(cls, uuid_document: args.PathUUIDDocument):
        """
        Updating **content** will result in the current
        document content being moved to an edit.

        To undo updates of the `content` field use **rollback** to revert to
        the most recent edit, or use `uuid_rollback` to specify the exact edit
        uuid to rollback to.

        When changing the public status of a document, bear in mind that it
        will remove the document from any collection where the owner does not
        have a grant on the document.

        To read the edits for a document use
        `GET /documents/{uuid_document}/edits`.
        """
        ...

    @classmethod
    def get_recent_document_edits(
        cls,
        uuid_document: args.PathUUIDDocument,
        read: DependsRead,
        param: Annotated[TimespanLimitParams, Depends()],
    ) -> AsOutput[EditSchema]:
        """Recent edits to a particular document."""

        data: Data[ResolvedDocument] = read.access.d_document(uuid_document)
        (document,) = data.data.documents

        q = document.q_select_edits(
            before=param.before_timestamp,
            after=param.after_timestamp,
            limit=param.limit,
        )
        res = read.session.execute(q)
        edits = tuple(res.scalars())
        return mwargs(
            AsOutput[EditSchema],
            data=TypeAdapter(List[EditSchema]).validate_python(edits),
        )

    @classmethod
    def get_document_rendered(
        cls,
        access: DependsAccess,
        uuid_document: args.PathUUIDDocument,
    ) -> FileResponse:
        """Read document content rendered."""
        raise HTTPException(400, detail="Not implemented yet.")
