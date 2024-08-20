# import asyncio
# import enum
# import json
# import secrets
# from typing import (Annotated, Any, AsyncGenerator, Dict, Generic, List, Self,
#                     Tuple, TypeVar)
#
# import httpx
# import typer
# import yaml
# from captura import __version__
# from captura.models import ChildrenAssignment, ChildrenGrant, Plural
# from captura.schemas import CollectionPostSchema, DocumentPostSchema, UserSchema
# from captura.views import AppView
# from pydantic import BaseModel, ConfigDict, Field, model_validator
#
# from legere import flags
# from legere.handlers import Handler
# from legere.requests import Requests
#
# from .requests import Requests
#
# # from pydantic.generics import GenericModel
#
# SpecResult = AsyncGenerator[httpx.Response | Tuple[httpx.Response], None]
#
#
# # NOTE: Distinguishes errors from `ApplyError` since cannot raise `typer.Exit`
# #       responsibly in many instances.
# class ApplyError(Exception):
#     @classmethod
#     def bad_mode(cls, bad: Any) -> Self:
#         msg = "expected one of `read`, `apply`, or `destroy`"
#         msg = f"Unknown mode {bad}, {msg}."
#         return cls(msg)
#
#     @classmethod
#     def cannot_match(cls, bad: Any) -> Self:
#         return cls(f"Cannot match `{bad}`.")
#
#
# class ApplyMode(enum.Enum):
#     read = "read"
#     apply = "apply"
#     destroy = "destroy"
#
#
# class ApplyState:
#     requests: Requests
#     mode: ApplyMode
#     handler: Handler
#
#     def __init__(self, requests: Requests, mode: ApplyMode, handler: Handler):
#         self.requests = requests
#         self.mode = mode
#         self.handler = handler
#
#
# # class ApplyStatus(BaseModel):
# #     uuid_status: Annotated[
# #         str,
# #         Field(default_factory=lambda: secrets.token_urlsafe(4)),
# #     ]
# #     uuid_status_previous: Annotated[str, Field()]
# #     uuid_obj: Annotated[str | None, Field(None)]
# #
# #     @classmethod
# #     def load(self, filepath: flags.ArgFilePath) -> str: ...
#
#
# class BaseAssoc(BaseModel):
#     # Collection/Document information.
#     kind_source: Annotated[ChildrenAssignment | None, Field(default=None)]
#     uuid_source: Annotated[str | None, Field(default=None)]
#
#     # Fill in one of these
#     name: Annotated[str | None, Field(default=None)]
#     uuid: Annotated[str | None, Field(default=None)]
#
#     @model_validator(mode="after")
#     def uuid_or_name(self) -> Self:
#         if (self.uuid is None) == (self.name is None):
#             raise ApplyError(
#                 "Specify exactly one of `uuid` and `name`. Got "
#                 f"`{self.uuid}` and `{self.name}`."
#             )
#
#         return self
#
#
# # class SpecGrant(BaseAssoc):
# #     async def resolve_uuid(self, state: ApplyState) -> str:
# #         if (name := self.name) is None:
# #             return self.uuid_source  # type: ignore
# #
# #         match self.kind_source:
# #             case ChildrenAssignment.documents:
# #                 res = await state.requests.documents.search(name_like=name)
# #             case ChildrenAssignment.collections:
# #                 res = await state.requests.collections.search(name_like=name)
# #             case _:
# #                 raise ApplyError("Unknown `kind_obj` `ChildrenAssignment`.")
# #
# #         if status := await state.handler.handle(res):
# #             raise typer.Exit(status)
# #         elif len(data := res.json()) != 1:
# #             raise ApplyError(f"Name `{name}` specifies many results.")
# #
# #         return data[0]["uuid"]
# #
# #     async def __call__(self, state: ApplyState) -> httpx.Response:
# #         client = state.requests.assignments
# #         documents, collections = client.documents, client.collections
# #         uuid_obj = [await self.resolve_uuid(state)]
# #
# #         if self.kind_source is None or self.uuid_source is None:
# #             raise ApplyError(
# #                 "`SpecAssignment` must define `kind_owner` and `uuid_owner` "
# #                 "to continue. These should either be specified directly or by"
# #                 "adding them from another called."
# #             )
# #
# #         match [state.mode, self.kind_source]:
# #             case ["apply", ChildrenAssignment.collections]:
# #                 res = await collections.create(self.uuid_source, uuid_obj)
# #             case ["apply", ChildrenAssignment.documents]:
# #                 res = await users.create(self.uuid_source, uuid_obj)
# #             case ["destroy", ChildrenAssignment.collections]:
# #                 res = await collections.delete(self.uuid_source, uuid_obj)
# #             case ["destroy", ChildrenAssignment.documents]:
# #                 res = await users.delete(self.uuid_source, uuid_obj)
# #             case [
# #                 _ as bad_mode,
# #                 ChildrenGrant.users | ChildrenGrant.documents,
# #             ]:
# #                 raise ApplyError.bad_mode(bad_mode)
# #             case ["apply" | "destroy", _ as bad]:
# #                 raise ApplyError(
# #                     f"Unknown source kind `{bad}` ` (expected one of "
# #                     "`documents` or `collection`)."
# #                 )
# #             case _ as bad:
# #                 raise ApplyError(f"Cannot match `{bad}`.")
# #
# #         if status := await state.handler.handle(res):
# #             raise typer.Exit(status)
# #         return res
#
#
# class SpecAssignment(BaseAssoc):
#     """For both :class:`CollectionApplySchema` and
#     :class:`DocumentApplySchema`.
#
#     :attr kind_source: The kind of object that the assignment is to be created
#         for. For instance, this could be `documents`.
#
#         This field should be set explicitly in YAML or by updating this object,
#         it is required for :meth:`__call__`.
#     :attr uuid_source: The uuid of the object that the assignment is to be
#         created for. This should be for an object of kind :attr:`kind_source`.
#
#         This field should be set explicitly in YAML or by updating this object,
#         it is required for :meth:`__call__`.
#     :attr name: Name of the target, e.g. if :attr:`kind_source` is
#         `collections` then this should be a document name.
#
#         Either this field or :attr:`uuid` is required.
#     :attr uuid: UUID of the target, e.g. if :attr:`kind_source` is
#         `collections` then this should be a document uuid.
#
#         Either this field or :attr:`uuid` is required.
#     """
#
#     async def resolve_uuid(
#         self, state: ApplyState
#     ) -> Tuple[httpx.Response | None, List[str]]:
#         if (name := self.name) is None:
#             return self.uuid_source  # type: ignore
#
#         match self.kind_source:
#             case ChildrenAssignment.documents:
#                 res = await state.requests.documents.search(name_like=name)
#             case ChildrenAssignment.collections:
#                 res = await state.requests.collections.search(name_like=name)
#             case _:
#                 raise ApplyError("Unknown `kind_obj` `ChildrenAssignment`.")
#
#         # if status := await state.handler.handle(res):
#         #     raise typer.Exit(status)
#         if len(data := res.json()) != 1:
#             raise ApplyError(f"Name `{name}` specifies many results.")
#
#         return res, [data[0]["uuid"]]
#
#     async def __call__(self, state: ApplyState) -> SpecResult:
#         client = state.requests.assignments
#         documents, collections = client.documents, client.collections
#
#         # NOTE: `res` will be returned to handler and checked there. Do not
#         #       check it there.
#         res, uuid_obj = await self.resolve_uuid(state)
#         if res is not None:
#             yield res
#
#         if self.kind_source is None or self.uuid_source is None:
#             raise ApplyError(
#                 "`SpecAssignment` must define `kind_owner` and `uuid_owner` "
#                 "to continue. These should either be specified directly or by"
#                 "adding them from another called."
#             )
#
#         match [state.mode, self.kind_source]:
#             case [ApplyMode.read, ChildrenAssignment.collections]:
#                 yield await collections.read(self.uuid_source, uuid_obj)
#             case [ApplyMode.read, ChildrenAssignment.documents]:
#                 yield await documents.read(self.uuid_source, uuid_obj)
#             case [ApplyMode.apply, ChildrenAssignment.collections]:
#                 yield await collections.create(self.uuid_source, uuid_obj)
#             case [ApplyMode.apply, ChildrenAssignment.documents]:
#                 yield await documents.create(self.uuid_source, uuid_obj)
#             case [ApplyMode.destroy, ChildrenAssignment.collections]:
#                 yield await collections.delete(self.uuid_source, uuid_obj)
#             case [ApplyMode.destroy, ChildrenAssignment.documents]:
#                 yield await documents.delete(self.uuid_source, uuid_obj)
#             case [
#                 _ as bad_mode,
#                 ChildrenAssignment.collections | ChildrenAssignment.documents,
#             ]:
#                 raise ApplyError.bad_mode(bad_mode)
#             case ["apply" | "destroy", _ as bad]:
#                 raise ApplyError(
#                     f"Unknown source kind `{bad}` ` (expected one of "
#                     "`documents` or `collection`)."
#                 )
#             case _ as bad:
#                 raise ApplyError.cannot_match(bad)
#
#         # await state.handler.handle(res)
#         # if status := await state.handler.handle(res):
#         #     raise typer.Exit(status)
#         return
#
#
# class SpecDocument(DocumentPostSchema):
#     collections: Annotated[
#         List[SpecAssignment] | None,
#         Field(default=None),
#     ]
#
#     # NOTE: Mode is considered by `SpecAssignment`.
#     async def handle_colllections(self, state: ApplyState) -> SpecResult:
#         if self.collections is None:
#             return
#
#         for collection in self.collections:
#             async for res in collection(state):
#                 yield res
#
#     async def __call__(self, state: ApplyState) -> SpecResult:
#         res, uuid_obj = await self.resolve_uuid(state)
#         if res is not None:
#             yield res
#
#         match state.mode:
#             case ApplyMode.apply:
#                 post = self.model_dump(exclude={"collections"})
#                 res = await state.requests.documents.create(post)
#                 yield res
#
#             case ApplyMode.destroy:
#                 # NOTE: Deletion should destroy assignments (to collections)
#                 uuid = await self.resolve_uuid(state)
#                 res = await state.requests.documents.delete(uuid)
#                 yield res
#
#             case _ as bad:
#                 raise ApplyError(f"Unknown mode `{bad}`.")
#
#         async for item in self.handle_colllections(state):
#             yield item
#
#     async def resolve_uuid(self, state: ApplyState) -> Tuple[httpx.Response, List[str]]:
#         # NOTE: Call only after `apply`.
#         res = await state.requests.documents.search(name_like=self.name)
#         if status := await state.handler.handle(res):
#             raise typer.Exit(status)
#
#         if len(data := res.json()) != 1:
#             raise ApplyError(f"Name `{self.name}` specifies many results.")
#
#         return res, [data[0]["uuid"]]
#
#
# class SpecCollection(CollectionPostSchema):
#     documents: Annotated[
#         List[SpecAssignment] | None,
#         Field(default=None),
#     ]
#
#     async def __call__(self, state: ApplyState) -> SpecResult:
#         match state.mode:
#             case ApplyMode.apply:
#                 post = self.model_dump(exclude={"collections"})
#                 res = await state.requests.collections.create(**post)
#                 yield res
#             case ApplyMode.destroy:
#                 # NOTE: Deletion should destroy assignments (to collections)
#                 uuid = await self.resolve_uuid(state)
#                 res = await state.requests.documents.delete(uuid)
#                 yield res
#             case _ as bad:
#                 raise ApplyError(f"Unknown mode `{bad}`.")
#
#     async def resolve_uuid(self, state: ApplyState) -> str:
#         # NOTE: Call only after `apply`.
#         res = await state.requests.collections.search(name_like=self.name)
#         if status := await state.handler.handle(res):
#             raise typer.Exit(status)
#
#         if len(data := res.json()) != 1:
#             raise ApplyError()
#
#         return data[0]["uuid"]
#
#
# class SpecUser(UserSchema):
#     documents: Annotated[List[SpecDocument] | None, Field(default=None)]
#     collections: Annotated[List[SpecCollection] | None, Field(default=None)]
#
#     async def __call__(self, state: ApplyState) -> SpecResult:
#         match state.mode:
#             case ApplyMode.apply:
#                 post = self.model_dump(exclude={"collections", "documents"})
#                 res = await state.requests.users.create(**post)
#                 yield res
#
#                 if status := await state.handler.handle(res):
#                     raise typer.Exit(status)
#
#                 if self.collections is not None:
#                     res = await asyncio.gather(
#                         collection(state) for collection in self.collections
#                     )
#                     yield res
#                     status = await state.handler.handle(res)
#                     if status:
#                         raise typer.Exit(status)
#                 if self.documents is not None:
#                     res = await asyncio.gather(
#                         document(state) for document in self.documents
#                     )
#                     yield res
#                     status = await state.handler.handle(res)
#                     if status:
#                         raise typer.Exit(status)
#             case ApplyMode.destroy:
#                 ...
#             case _:
#                 raise ApplyError()
#
#
# # NOTE: Singular naming has to be consistent with kind object.
# class Specs(enum.Enum):
#     documents = SpecDocument
#     collections = SpecCollection
#     users = SpecUser
#     assignments = SpecAssignment
#
#
# Spec = SpecUser | SpecCollection | SpecDocument | SpecAssignment
# T = TypeVar(
#     "T",
#     SpecUser,
#     SpecCollection,
#     SpecDocument,
#     SpecAssignment,
#     List[SpecUser],
#     List[SpecCollection],
#     List[SpecDocument],
#     List[SpecAssignment],
# )
#
#
# # NOTE: Holy fuck, this is awesome.
# class ObjectSchema(BaseModel, Generic[T]):
#     api_version: Annotated[str, Field(default=__version__)]
#     kind: Annotated[Plural, Field()]
#     spec: Annotated[T, Field()]
#
#     model_config = ConfigDict()
#
#     @model_validator(mode="before")
#     @classmethod
#     def validate_spec_type(cls, values: Any) -> Any:
#         value = values.get("spec")
#         if not isinstance(value, dict) and not isinstance(value, list):
#             return value
#
#         if (
#             (kind := values.get("kind")) is None
#             or isinstance(kind, Plural)
#             or kind == "list"
#         ):
#             return values
#         if kind in Plural.__members__:
#             kind = Plural.__members__[kind]
#         elif kind in Plural._value2member_map_:
#             kind = Plural._value2member_map_[kind]
#         else:
#             msg = str(tuple(Plural.__members__))
#             msg = f"Unknown object kind `{kind}`. Expected any of `{msg}`."
#             raise ValueError(msg)
#
#         TT = Specs[kind.value]
#         values.update(spec=TT.value.model_validate(value))
#         return values
#
#     # NOTE: Do not raise `typer.Exit` here since writing this such that data
#     #       classes do not contain typer. For the typerized function see
#     #       `ApplyMixins.apply`.
#     @classmethod
#     def load(cls, filepath: flags.ArgFilePath) -> Self:
#         with open(filepath, "r") as file:
#             data = yaml.safe_load(file)
#
#         if not isinstance(data, dict):
#             raise ApplyError(f"`{filepath}` must deserialize to a dictionary.")
#
#         return cls.model_validate(data)
#
#     async def __call__(self, state: ApplyState) -> AsyncGenerator[httpx.Response, None]:
#         match self.spec:
#             # case list() as items:
#             #     return await asyncio.gather(item(state) for item in items)
#             case (
#                 SpecUser()
#                 | SpecDocument()
#                 | SpecCollection()
#                 | SpecAssignment()
#                 # | SpecGrant()
#             ):
#                 return self.spec(state)
#             case _:
#                 raise ApplyError(f"No spec for `{type(self.spec)}`.")
#
#
# class ApplyMixins:
#     _state: ApplyState | None
#
#     @property
#     def state(self) -> ApplyState:
#         # SHOULD NOT EXIT GRACEFULLY. THIS HAPPENS WHEN BAD IMPL
#         if self._state is None:
#             raise ApplyError("State is missing.")
#         return self._state
#
#     # DECORATE THESE.
#     # async def read(
#     #     self,
#     #     filepath: flags.ArgFilePath,
#     # ) -> AsyncGenerator[httpx.Response, None]:
#     #     # self.state.mode = ApplyMode.read
#     #     # data = ObjectSchema.load(filepath)
#     #     # await data(self.state)
#     #
#     #     for item in "abcd1234":
#     #         await asyncio.sleep(1)
#     #         yield item
#     #
#     # async def apply(
#     #     self,
#     #     filepath: flags.ArgFilePath,
#     # ) -> AsyncGenerator[httpx.Response, None]:
#     #     data = self.load(filepath)
#     #     data(self.state)
#     #
#     # async def destroy(
#     #     self,
#     #     filepath: flags.ArgFilePath,
#     # ) -> AsyncGenerator[httpx.Response, None]:
#     #     data = self.load(filepath)
#     #     await data(self.state)
#
#
# async def apply(
#     bind,
#     state: ApplyState,
#     filepath: flags.ArgFilePath,
# ) -> AsyncGenerator[httpx.Response, None]:
#
#     app, config = None, state.requests.config
#     if not app:
#         app = AppView.view_router
#
#     async with httpx.AsyncClient(
#         base_url=config.host.remote,
#         app=app,
#     ) as client:
#         bind._client = client
#
#         # match self.state.mode:
#         #     case ApplyMode.read:
#         #         stream = self.read(filepath)
#         #     case ApplyMode.apply:
#         #         stream = self.apply(filepath)
#         #     case ApplyMode.destroy:
#         #         stream = self.destroy(filepath)
#         #
#         data = ObjectSchema.load(filepath)
#         stream = data(self.state)
#         async for thing in await stream:
#             yield thing
