# """
# This module will attempt to figure what what will be needed to build an
# extension.
#
# """
#
# from typing import Generic, List, Tuple, TypeVar
#
# from app.views.base import BaseView
# from client import BaseTyperizable
#
# T_ContentUser = TypeVar("T_ContentUser")
# T_ContentDocument = TypeVar("T_ContentDocument")
# T_ContentCollection = TypeVar("T_ContentCollection")
#
#
# # NOTE: T_Content will have to parametrize schemas.
# class Plugin(Generic[T_ContentUser, T_ContentDocument, T_ContentCollection]):
#
#     views: List[BaseView]
#     commands: List[BaseTyperizable]
#
#     TypeContentUser: T_ContentUser | None
#     TypeContentCollection: T_ContentCollection | None
#     TypeContentDocument: T_ContentDocument
#
#     def __init__(
#         self,
#         views: List[BaseView] | BaseView,
#         commands: List[BaseTyperizable] | BaseTyperizable,
#         TypeContentUser: T_ContentUser,
#         TypeContentDocument: T_ContentDocument,
#         TypeContentCollection: T_ContentCollection,
#     ):
#         if not isinstance(views, list):
#             views = [views]
#
#         if not isinstance(commands, list):
#             commands = [commands]
#
#         self.views, self.commands = views, commands
#         self.TypeContentUser = TypeContentUser
#         self.TypeContentDocument = TypeContentDocument
#         self.TypeContentCollection = TypeContentCollection
#
#     @property
#     def app(
#         self,
#     ) -> BaseView[
#         T_ContentUser,
#         T_ContentDocument,
#         T_ContentCollection,
#     ]: ...
#
#     @property
#     def client(
#         self,
#     ) -> BaseTyperizable[
#         T_ContentUser,
#         T_ContentDocument,
#         T_ContentCollection,
#     ]: ...
#
#
# # ----
# ...
