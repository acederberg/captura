import functools
from typing import (Callable, Concatenate, Generator, List, Literal, ParamSpec,
                    Set, Tuple, Type, TypeVar)

from app import __version__, util
from app.controllers.access import Access, WithAccess, with_access
from app.controllers.base import (BaseController, Data, ResolvedEvent,
                                  ResolvedObjectEvents)
from app.depends import (DependsAccess, DependsDelete, DependsRead,
                         DependsSessionMaker, DependsToken)
from app.models import (AnyModel, Assignment, Collection, Document, Event,
                        Grant, KindEvent, KindObject, KindRecurse,
                        ResolvableSingular, Singular, T_Resolvable, Tables,
                        User)
from app.schemas import (AsOutput, AssignmentExtraSchema,
                         CollectionExtraSchema, DocumentExtraSchema,
                         DocumentMetadataSchema, EventBaseSchema,
                         EventExtraSchema, EventMetadataSchema, EventParams,
                         EventSchema, EventSearchSchema, GrantExtraSchema,
                         KindSchema, OutputWithEvents, T_Output,
                         UserExtraSchema, mwargs, registry)
from app.views import args
from app.views.base import BaseView, OpenApiResponseCommon, OpenApiTags
from fastapi import Depends, HTTPException, Query, Request
from fastapi.routing import get_request_handler
from pydantic import TypeAdapter
from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
# Decorators.
#
# Typing voodoo (from hell).

T_admin_only_controller = TypeVar("T_admin_only_controller", bound=Access | WithAccess)
T_admin_only_return = TypeVar("T_admin_only_return")
T_admin_only_self = TypeVar("T_admin_only_self", bound=Type[BaseView])
P_admin_only = ParamSpec("P_admin_only")
CallableControllerFirst = Callable[
    Concatenate[T_admin_only_self, T_admin_only_controller, P_admin_only],
    T_admin_only_return,
]


def admin_only(
    fn: CallableControllerFirst[
        T_admin_only_self, T_admin_only_controller, P_admin_only, T_admin_only_return
    ],
) -> CallableControllerFirst[
    T_admin_only_self, T_admin_only_controller, P_admin_only, T_admin_only_return
]:

    @functools.wraps(fn)
    def wrapper(
        cls: Type[BaseView],
        access: T_admin_only_controller,
        *args: P_admin_only.args,
        **kwargs: P_admin_only.kwargs,
    ):

        if not access.token.admin:
            detail = "This endpoint is for admins only."
            raise HTTPException(403, detail=detail)
        return fn(cls, access, *args, **kwargs)

    return wrapper


# NOTE: Mounted directly on app. Easier to maintain here.
class EventSearchView(BaseView):

    view_routes = dict(
        get_event_objects="/events/{uuid_event}/objects",
        get_user_events="/users/{uuid_user}/events",
        get_document_events="/documents/{uuid_document}/events",
        get_collection_events="/collections/{uuid_collection}/events",
        get_grant_events="/documents/{uuid_document}/users/{uuid_user}/events",
        get_assignment_events="/documents/{uuid_document}/collections/{uuid_collection}/events",
    )

    view_router_args = dict(
        tags=[OpenApiTags.events],
        responses=OpenApiResponseCommon,
    )

    # @classmethod
    # def object_events(
    #     cls,
    #     Schema: Type[T_Output],
    #     read: DependsRead,
    #     resolvable_object: ResolvableSingular[T_Resolvable],
    #     resolvable_object_kind: KindObject,
    #     param: EventParams,
    # ) -> OutputWithEvents[T_Output]:
    #
    #     item, events = read.object_events(resolvable_object, resolvable_object_kind, param,)
    #     return mwargs(
    #         OutputWithEvents[Schema],
    #         events=events,
    #         data=TypeAdapter(Schema).validate_python(item),
    #     )

    @classmethod
    @admin_only
    def get_event_objects(
        cls,
        access: DependsAccess,
        uuid_event: args.PathUUIDEvent,
        param: EventParams = Depends(),
    ) -> AsOutput[EventExtraSchema]:
        """Restore a deletion from an event."""

        data: Data[ResolvedEvent] = access.d_event(uuid_event)
        event = data.data.events[0]

        if param.root:
            event = event.find_root(access.session)

        return mwargs(
            AsOutput[EventExtraSchema],
            data=EventExtraSchema.model_validate(event),
        )

    @classmethod
    @admin_only
    def get_user_events(
        cls,
        access: DependsAccess,
        uuid_user: args.PathUUIDUser,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[UserExtraSchema]:

        data: Data[ResolvedObjectEvents]
        data = access.d_object_events(uuid_user, KindObject.user, param)
        return mwargs(
            OutputWithEvents[UserExtraSchema],
            events=data.data.events,
            data=UserExtraSchema.model_validate(data.data.obj),
        )

    @classmethod
    @admin_only
    def get_document_events(
        cls,
        access: DependsAccess,
        read: DependsRead,
        uuid_document: args.PathUUIDUser,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[DocumentExtraSchema]:
        item, events = read.object_events(uuid_document, KindObject.document, param)
        return mwargs(
            OutputWithEvents[DocumentExtraSchema],
            events=events,
            data=DocumentExtraSchema.model_validate(item),
        )

    @classmethod
    @admin_only
    def get_collection_events(
        cls,
        access: DependsAccess,
        read: DependsRead,
        uuid_collection: args.PathUUIDUser,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[CollectionExtraSchema]:
        item, events = read.object_events(uuid_collection, KindObject.collection, param)
        return mwargs(
            OutputWithEvents[CollectionExtraSchema],
            events=events,
            data=CollectionExtraSchema.model_validate(item),
        )

    @classmethod
    @admin_only
    def get_grant_events(
        cls,
        access: DependsAccess,
        read: DependsRead,
        uuid_document: args.PathUUIDDocument,
        uuid_user: args.PathUUIDUser,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[GrantExtraSchema]:

        session = access.session
        document = Document.resolve(session, uuid_document)
        user = User.resolve(session, uuid_user)
        grants = Grant.resolve_from_target(session, user, {document.uuid})
        if len(grants) != 1:
            raise HTTPException(500)
        (grant,) = grants

        item, events = read.object_events(grant, KindObject.grant, param)
        return mwargs(
            OutputWithEvents[GrantExtraSchema],
            events=events,
            data=GrantExtraSchema.model_validate(item),
        )

    @classmethod
    @admin_only
    def get_assignment_events(
        cls,
        access: DependsAccess,
        read: DependsRead,
        uuid_document: args.PathUUIDCollection,
        uuid_collection: args.PathUUIDDocument,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[AssignmentExtraSchema]:

        session = access.session
        document = Document.resolve(session, uuid_document)
        collection = Collection.resolve(session, uuid_collection)
        grants = Assignment.resolve_from_target(session, collection, {document.uuid})

        if len(grants) != 1:
            raise HTTPException(500)
        (grant,) = grants

        item, events = read.object_events(grant, KindObject.grant, param)
        return mwargs(
            OutputWithEvents[AssignmentExtraSchema],
            events=events,
            data=AssignmentExtraSchema.model_validate(item),
        )


class EventView(BaseView):
    """
    ..
        NOTE: Events should never return results in flattened format from
              anywhere besides here.
    """

    view_routes = dict(
        get_event="/{uuid_event}",
        get_events="",
        delete_prune_event="/{uuid_event}",
        delete_prune_object_events="/{kind_obj}/{uuid_obj}",
        patch_undo_event="/{uuid_event}/objects",
    )
    view_router_args = dict(
        tags=[OpenApiTags.events],
        responses=OpenApiResponseCommon,
    )

    @classmethod
    @admin_only
    def delete_prune_event(
        cls,
        access: DependsAccess,
        delete: DependsDelete,
        uuid_event: args.PathUUIDEvent,
        param: EventParams = Depends(),
    ) -> OutputWithEvents[EventSchema]:

        session = access.session
        event = Event.resolve(session, uuid_event)
        if param.root:
            event = event.find_root()

        event_serial = EventSchema.model_validate(event)
        data = delete.event(
            mwargs(
                Data[ResolvedEvent],
                data=mwargs(ResolvedEvent, events=(event,)),
            )
        )

        return mwargs(
            OutputWithEvents[EventSchema],
            data=event_serial,
            events=[EventSchema.model_validate(data.event)],
        )

    @classmethod
    @admin_only
    def delete_prune_object_events(
        cls,
        access: DependsAccess,
        delete: DependsDelete,
        kind_obj: Literal["users", "documents", "collections"],
        uuid_obj: args.PathUUIDObj,
        param: EventParams = Depends(),
    ) -> AsOutput[EventSchema]:

        data = delete.a_object_events(
            uuid_obj,
            KindObject(kind_obj),
            param,
            exclude_deleted=False,
        )

        return mwargs(
            AsOutput[EventSchema],
            data=EventSchema.model_validate(data.event),
        )

    @classmethod
    @admin_only
    def get_event(
        cls,
        access: DependsAccess,
        uuid_event: args.PathUUIDEvent,
        param: EventParams = Depends(),
    ) -> AsOutput[EventSchema]:

        session = access.session
        event = Event.resolve(session, uuid_event)
        if param.root:
            event = event.find_root(session)

        return mwargs(AsOutput[EventSchema], data=EventSchema.model_validate(event))

    @classmethod
    def get_events(
        cls,
        access: DependsAccess,
        param_search: EventSearchSchema = Depends(),
    ) -> AsOutput[List[EventMetadataSchema]]:

        # NOTE: Build the search.
        kwargs_search = param_search.model_dump(exclude={"before", "after"})
        if not access.token.admin:
            kwargs_search.update(uuid_user=access.token_user.uuid)
        print(kwargs_search)

        session = access.session
        q = Event.q_select_search(
            **kwargs_search,
            before=(
                int(param_search.before.timestamp())
                if param_search.before is not None
                else None
            ),
            after=int(param_search.after.timestamp()),
        )
        util.sql(session, q)
        events = session.execute(q).scalars()

        data = TypeAdapter(List[EventMetadataSchema]).validate_python(events)
        return mwargs(AsOutput, data=data)

    @classmethod
    def patch_undo_event(
        cls,
        delete: DependsDelete,
        uuid_event: args.PathUUIDUser,
    ) -> OutputWithEvents[EventSchema]:
        """Restore a deletion from an event.

        Return the events and updated objects.

        :param dry_run:
        """

        event = (
            delete.access.event(uuid_event)
            .check_kind(KindEvent.delete)
            .check_not_undone()
        )
        delete.access.token_user.check_can_access_event(event)

        event = (
            delete.access.event(event.find_root())
            .check_kind(KindEvent.delete)
            .check_not_undone()
        )
        delete.access.token_user.check_can_access_event(event)

        data = delete.event(
            mwargs(
                Data[ResolvedEvent],
                data=mwargs(ResolvedEvent, events=(event,)),
            )
        )

        return mwargs(
            OutputWithEvents[EventSchema],
            data=EventSchema.model_validate(event),
            event=data.event,
        )

    # NOTE: This will be implemented individually in each `DELETE` because
    #       access will be handled already and data will have instantiated.
    @classmethod
    def patch_restore_object(
        cls,
        delete: DependsDelete,
        kind_object: args.KindObject,
        uuid_object: args.PathUUIDObj,
    ): ...

    # TODO: Finish this later when time exists for it.
    # @classmethod
    # async def ws_events(
    #     cls,
    #     websocket: WebSocket,
    #     sessionmaker: DependsAsyncSessionMaker,
    #     token: DependsToken,
    #     param: EventSearchSchema = Depends(),
    #     flatten: args.QueryFlat = True,
    #     kind_recurse: args.QueryKindRecurse = KindRecurse.depth_first,
    #     wait: Annotated[int, args.Query(gt=1, lt=60)] = 1,
    # ) -> None:
    #     WS_MAX_LIFETIME: int = 36000
    #
    #     await websocket.accept()
    #     timestamp_connection_start = int(datetime.timestamp(datetime.now()))
    #     lifetime = 0
    #
    #     while (lifetime := lifetime + wait) < WS_MAX_LIFETIME:
    #         # events = await cls.get_events(
    #         #     sessionmaker,
    #         #     token,
    #         #     param=param,
    #         #     flatten=flatten,
    #         #     kind_recurse=kind_recurse,
    #         # )
    #         # await websocket.send_json(events)
    #         # await asyncio.sleep(wait)
    #         text = await websocket.receive_text()
    #         await websocket.send(f"text = `{text}`.")
    #
    #     ...
