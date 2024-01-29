from pydantic.generics import GenericModel
import asyncio
import typing

from typing import AsyncGenerator, TypeVar, Generic
import enum
from os import path
from typing import Annotated, List, Set, Type, TypeAlias
from typing_extensions import Self
import typer

import yaml

from client import flags
import httpx
from pydantic import BaseModel, Field, field_validator, model_validator
from app.models import KindObject, ChildrenAssignment
from app.schemas import (
    CollectionSchema,
    UserSchema,
    DocumentPostSchema,
    CollectionPostSchema,
    DocumentSchema,
)
from app import __version__
from client.base import BaseRequest
from client.handlers import ConsoleHandler, Handler
from client.requests import Requests


class Mode(enum.Enum):
    apply = "apply"
    destroy = "destroy"


class CommandState:
    requests: Requests
    mode: Mode
    handler: Handler
    # data: Dict[str, Any]

    def __init__(self, requests: Requests, mode: Mode, handler: Handler):
        self.requests = requests
        self.mode = mode
        self.handler = handler


class SpecAssignment(BaseModel):
    """For both :class:`CollectionApplySchema` and
    :class:`DocumentApplySchema`.

    :attr kind_source: The kind of object that the assignment is to be created
        for. For instance, this could be `documents`.

        This field should be set explicitly in YAML or by updating this object,
        it is required for :meth:`__call__`.
    :attr uuid_source: The uuid of the object that the assignment is to be
        created for. This should be for an object of kind :attr:`kind_source`.

        This field should be set explicitly in YAML or by updating this object,
        it is required for :meth:`__call__`.
    :attr name: Name of the target, e.g. if :attr:`kind_source` is
        `collections` then this should be a document name.

        Either this field or :attr:`uuid` is required.
    :attr uuid: UUID of the target, e.g. if :attr:`kind_source` is
        `collections` then this should be a document uuid.

        Either this field or :attr:`uuid` is required.
    """

    # Collection/Document information.
    kind_source: Annotated[ChildrenAssignment | None, Field(default=None)]
    uuid_source: Annotated[str | None, Field(default=None)]

    # Fill in one of these
    name: Annotated[str | None, Field(default=None)]
    uuid: Annotated[str | None, Field(default=None)]

    @model_validator(mode="after")
    def uuid_or_name(self) -> Self:
        if not (self.uuid is None) == (self.name is None):
            raise ValueError("Specify exactly one of `uuid_obj` and `kind_obj`.")

        return self

    async def __call__(self, state: CommandState) -> httpx.Response:
        client = state.requests.assignments
        documents, collections = client.documents, client.collections
        uuid_obj = [await self.resolve_uuid(state)]

        if self.kind_source is None or self.uuid_source is None:
            raise ValueError(
                "`SpecAssignment` must define `kind_owner` and `uuid_owner` "
                "to continue. These should either be specified directly or by"
                "adding them from another called."
            )

        match [state.mode, self.kind_source]:
            case ["apply", ChildrenAssignment.collections]:
                res = await collections.create(self.uuid_source, uuid_obj)
            case ["apply", ChildrenAssignment.documents]:
                res = await documents.create(self.uuid_source, uuid_obj)
            case ["destroy", ChildrenAssignment.collections]:
                res = await collections.delete(self.uuid_source, uuid_obj)
            case ["destroy", ChildrenAssignment.documents]:
                res = await documents.delete(self.uuid_source, uuid_obj)
            case [_ as bad_mode, _ as bad]:
                raise ValueError(
                    f"Unknown mode `{bad_mode}` (should be one of 'apply' or "
                    f"'destroy') or source kind `{bad}` ` (expected one of "
                    "`documents` or `collection`)."
                )

        if status := await state.handler.handle(res):
            raise typer.Exit(status)
        return res

    async def resolve_uuid(self, state: CommandState) -> str:
        if (name := self.name) is None:
            return self.uuid_source  # type: ignore

        match self.kind_source:
            case ChildrenAssignment.documents:
                res = await state.requests.documents.search(name_like=name)
            case ChildrenAssignment.collections:
                res = await state.requests.collections.search(name_like=name)
            case _:
                raise ValueError("Unknown `kind_obj` `ChildrenAssignment`.")

        if status := await state.handler.handle(res):
            raise typer.Exit(status)
        elif len(data := res.json()) != 1:
            raise ValueError("")

        return data[0]["uuid"]


class SpecDocument(DocumentPostSchema):
    collections: Annotated[
        List[SpecAssignment] | None,
        Field(default=None),
    ]

    async def __call__(self, state: CommandState) -> None:
        match state.mode:
            case Mode.apply:
                post = self.model_dump(exclude={"collections"})
                res = await state.requests.documents.create(post)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)

                if self.collections is not None:
                    res = await asyncio.gather(
                        collection(state) for collection in self.collections
                    )
                    status = await state.handler.handle(res)
                    if status:
                        raise typer.Exit(status)

            case Mode.destroy:
                # NOTE: Deletion should destroy assignments (to collections)
                uuid = await self.resolve_uuid(state)
                res = await state.requests.documents.delete(uuid)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)
            case _:
                raise ValueError()

    async def resolve_uuid(self, state: CommandState) -> str:
        # NOTE: Call only after `apply`.
        res = await state.requests.documents.search(name_like=self.name)
        if status := await state.handler.handle(res):
            raise typer.Exit(status)

        if len(data := res.json()) != 1:
            raise ValueError()

        return data[0]["uuid"]


class SpecCollection(CollectionPostSchema):
    documents: Annotated[
        List[SpecAssignment] | None,
        Field(default=None),
    ]

    async def __call__(self, state: CommandState) -> httpx.Response:
        match state.mode:
            case Mode.apply:
                post = self.model_dump(exclude={"collections"})
                res = await state.requests.collections.create(post)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)

                if self.documents is not None:
                    res = await asyncio.gather(
                        document(state) for document in self.documents
                    )
                    if status := await state.handler.handle(res):
                        raise typer.Exit(status)
            case Mode.destroy:
                # NOTE: Deletion should destroy assignments (to collections)
                uuid = await self.resolve_uuid(state)
                res = await state.requests.documents.delete(uuid)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)
            case _:
                raise ValueError()

    async def resolve_uuid(self, state: CommandState) -> str:
        # NOTE: Call only after `apply`.
        res = await state.requests.collections.search(name_like=self.name)
        if status := await state.handler.handle(res):
            raise typer.Exit(status)

        if len(data := res.json()) != 1:
            raise ValueError()

        return data[0]["uuid"]


class SpecUser(UserSchema):
    documents: Annotated[List[SpecDocument] | None, Field(default=None)]
    collections: Annotated[List[SpecCollection] | None, Field(default=None)]

    async def __call__(self, state: CommandState) -> None:
        match state.mode:
            case Mode.apply:
                post = self.model_dump(exclude={"collections", "documents"})
                res = await state.requests.users.create(**post)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)

                if self.collections is not None:
                    res = await asyncio.gather(
                        collection(state) for collection in self.collections
                    )
                    status = await state.handler.handle(res)
                    if status:
                        raise typer.Exit(status)
                if self.documents is not None:
                    res = await asyncio.gather(
                        document(state) for document in self.documents
                    )
                    status = await state.handler.handle(res)
                    if status:
                        raise typer.Exit(status)
            case Mode.destroy:
                ...
            case _:
                raise ValueError()


class Specs(enum.Enum):
    documents = SpecDocument
    collections = SpecCollection
    users = SpecUser
    assignments = SpecAssignment


Spec = SpecUser | SpecCollection | SpecDocument | SpecAssignment


T = TypeVar("T", SpecUser, SpecCollection, SpecDocument, SpecAssignment)


# NOTE: Holy fuck, this is awesome.
class ObjectSchema(GenericModel, Generic[T]):
    api_version: Annotated[str, Field(default=__version__)]
    kind: Annotated[KindObject, Field()]
    spec: Annotated[T, Field()]

    @field_validator("spec", mode="before")
    def validate_spec_type(cls, value, values) -> Spec:
        if not isinstance(value, dict) and not isinstance(value, list):
            return value

        kind = values["kind"]
        if kind not in Specs:
            raise ValueError(f"Unknown object kind `{kind}`.")

        TT = Specs[kind]
        return TT.value.model_validate(value)

    async def __call__(self, state: CommandState):
        return await self.spec(state)


class Batch(BaseRequest):
    command = "object"
    commands = ("apply", "destroy")

    def load(self, filepath: flags.ArgFilePath) -> ObjectSchema:
        with open(filepath, "r") as file:
            data = yaml.safe_load(file)
        return ObjectSchema.model_validate(data)

    def apply(self, filepath: flags.ArgFilePath) -> httpx.Request:
        """I want something like `kubectl apply` because often I have data I
        want to post and delete but I'd rather not write the args out so often
        as this can become annoying.

        See also :func:`destroy`."""

        ...

    def destroy(filepath: flags.ArgFilePath) -> httpx.Request:
        ...
