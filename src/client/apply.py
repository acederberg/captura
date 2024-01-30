import asyncio
import enum
import json
from typing import Annotated, Any, Dict, Generic, List, Self, Tuple, TypeVar

import httpx
import typer
import yaml
from app import __version__
from app.models import ChildrenAssignment, Plural
from app.schemas import CollectionPostSchema, DocumentPostSchema, UserSchema
from pydantic import BaseModel, ConfigDict, Field, model_validator

from client import flags
from client.handlers import CONSOLE, Handler
from client.requests import Requests

from .requests import Requests

# from pydantic.generics import GenericModel


# NOTE: Distinguishes errors from `ApplyError` since cannot raise `typer.Exit`
#       responsibly in many instances.
class ApplyError(Exception):
    @classmethod
    def bad_mode(cls, bad: Any) -> Self:
        msg = f"Unknown mode {bad}, expected one of `apply` or `destroy`."
        return cls(msg)

    msg_vegue = ""


class ApplyMode(enum.Enum):
    apply = "apply"
    destroy = "destroy"


class ApplyState:
    requests: Requests
    mode: ApplyMode
    handler: Handler

    def __init__(self, requests: Requests, mode: ApplyMode, handler: Handler):
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
        if (self.uuid is None) == (self.name is None):
            raise ApplyError(
                "Specify exactly one of `uuid` and `name`. Got "
                f"`{self.uuid}` and `{self.name}`."
            )

        return self

    async def __call__(self, state: ApplyState) -> httpx.Response:
        client = state.requests.assignments
        documents, collections = client.documents, client.collections
        uuid_obj = [await self.resolve_uuid(state)]

        if self.kind_source is None or self.uuid_source is None:
            raise ApplyError(
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
            case [
                _ as bad_mode,
                ChildrenAssignment.collections | ChildrenAssignment.documents,
            ]:
                raise ApplyError.bad_mode(bad_mode)

            case ["apply" | "destroy", _ as bad]:
                raise ApplyError(
                    f"Unknown source kind `{bad}` ` (expected one of "
                    "`documents` or `collection`)."
                )

        if status := await state.handler.handle(res):
            raise typer.Exit(status)
        return res

    async def resolve_uuid(self, state: ApplyState) -> str:
        if (name := self.name) is None:
            return self.uuid_source  # type: ignore

        match self.kind_source:
            case ChildrenAssignment.documents:
                res = await state.requests.documents.search(name_like=name)
            case ChildrenAssignment.collections:
                res = await state.requests.collections.search(name_like=name)
            case _:
                raise ApplyError("Unknown `kind_obj` `ChildrenAssignment`.")

        if status := await state.handler.handle(res):
            raise typer.Exit(status)
        elif len(data := res.json()) != 1:
            raise ApplyError(f"Name `{name}` specifies many results.")

        return data[0]["uuid"]


class SpecDocument(DocumentPostSchema):
    collections: Annotated[
        List[SpecAssignment] | None,
        Field(default=None),
    ]

    async def __call__(self, state: ApplyState) -> None:
        match state.mode:
            case ApplyMode.apply:
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

            case ApplyMode.destroy:
                # NOTE: Deletion should destroy assignments (to collections)
                uuid = await self.resolve_uuid(state)
                res = await state.requests.documents.delete(uuid)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)
            case _ as bad:
                raise ApplyError(f"Unknown mode `{bad}`.")

    async def resolve_uuid(self, state: ApplyState) -> str:
        # NOTE: Call only after `apply`.
        res = await state.requests.documents.search(name_like=self.name)
        if status := await state.handler.handle(res):
            raise typer.Exit(status)

        if len(data := res.json()) != 1:
            raise ApplyError(f"Name `{name}` specifies many results.")

        return data[0]["uuid"]


class SpecCollection(CollectionPostSchema):
    documents: Annotated[
        List[SpecAssignment] | None,
        Field(default=None),
    ]

    async def __call__(self, state: ApplyState) -> httpx.Response:
        match state.mode:
            case ApplyMode.apply:
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
            case ApplyMode.destroy:
                # NOTE: Deletion should destroy assignments (to collections)
                uuid = await self.resolve_uuid(state)
                res = await state.requests.documents.delete(uuid)
                if status := await state.handler.handle(res):
                    raise typer.Exit(status)
            case _ as bad:
                raise ApplyError(f"Unknown mode `{bad}`.")

    async def resolve_uuid(self, state: ApplyState) -> str:
        # NOTE: Call only after `apply`.
        res = await state.requests.collections.search(name_like=self.name)
        if status := await state.handler.handle(res):
            raise typer.Exit(status)

        if len(data := res.json()) != 1:
            raise ApplyError()

        return data[0]["uuid"]


class SpecUser(UserSchema):
    documents: Annotated[List[SpecDocument] | None, Field(default=None)]
    collections: Annotated[List[SpecCollection] | None, Field(default=None)]

    async def __call__(self, state: ApplyState) -> None:
        match state.mode:
            case ApplyMode.apply:
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
            case ApplyMode.destroy:
                ...
            case _:
                raise ApplyError()


# NOTE: Singular naming has to be consistent with kind object.
class Specs(enum.Enum):
    documents = SpecDocument
    collections = SpecCollection
    users = SpecUser
    assignments = SpecAssignment


Spec = SpecUser | SpecCollection | SpecDocument | SpecAssignment
T = TypeVar("T", SpecUser, SpecCollection, SpecDocument, SpecAssignment)


# NOTE: Holy fuck, this is awesome.
class ObjectSchema(BaseModel, Generic[T]):
    api_version: Annotated[str, Field(default=__version__)]
    kind: Annotated[Plural, Field()]
    spec: Annotated[T, Field()]

    model_config = ConfigDict()

    @model_validator(mode="before")
    @classmethod
    def validate_spec_type(cls, values: Any) -> Any:
        value = values.get("spec")
        if not isinstance(value, dict) and not isinstance(value, list):
            return value

        kind = values.get("kind")
        if kind is None or isinstance(kind, Plural):
            return values
        if kind in Plural.__members__:
            kind = Plural.__members__[kind]
        elif kind in Plural._value2member_map_:
            kind = Plural._value2member_map_[kind]
        else:
            msg = str(tuple(Plural.__members__))
            msg = f"Unknown object kind `{kind}`. Expected any of `{msg}`."
            raise ValueError(msg)

        TT = Specs[kind.value]
        values.update(spec=TT.value.model_validate(value))
        return values

    # NOTE: Do not raise `typer.Exit` here since writing this such that data
    #       classes do not contain typer. For the typerized function see
    #       `ApplyMixins.apply`.
    @classmethod
    def load(cls, filepath: flags.ArgFilePath) -> Self:
        with open(filepath, "r") as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ApplyError(f"`{filepath}` must deserialize to a dictionary.")
        return cls.model_validate(data)

    async def __call__(self, state: ApplyState):
        return await self.spec(state)


class ApplyMixins:
    state: ApplyState | None

    def load(self, filepath: flags.ArgFilePath) -> ObjectSchema:
        try:
            res = ObjectSchema.load(filepath)
            CONSOLE.print_json(res := json.dumps(res.model_dump()))
        except ApplyError as err:
            CONSOLE.print(f"[red]{err}")
            raise typer.Exit()
        return res

    async def apply(self, filepath: flags.ArgFilePath) -> Tuple[httpx.Response, ...]:
        data = self.load(filepath)
        return tuple()

    async def destroy(self, filepath: flags.ArgFilePath) -> Tuple[httpx.Response, ...]:
        return tuple()
