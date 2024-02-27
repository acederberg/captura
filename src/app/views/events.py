from typing import Generator, List, Set, Tuple, TypeVar

from app import __version__
from app.depends import DependsSessionMaker, DependsToken
from app.models import (AnyModel, Event, KindEvent, KindObject, KindRecurse,
                        Tables, User)
from app.schemas import (EventActionSchema, EventBaseSchema, EventSchema,
                         EventSearchSchema, EventWithRootSchema)
from app.views import args
from app.views.base import BaseView
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session


class EventView(BaseView):
    """
    ..
        NOTE: Events should never return results in flattened format from
              anywhere besides here.
    """

    view_routes = dict(
        get_event="/{uuid_event}",
        delete_event="/{uuid_event}",
        get_events="",
        patch_undo_event="/{uuid_event}/objects",
        # patch_object="/{uuid_event}/objects/restore/{uuid_obj}",
        get_event_objects="/{uuid_event}/objects",
    )

    @classmethod
    def delete_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: args.PathUUIDEvent,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            event_root = event.find_root()
            session.delete(event_root)
            session.commit()
            event = Event(
                api_version=__version__,
                api_origin="DELETE /events/<uuid>",
                detail="Event deleted.",
                kind=KindEvent.delete,
                kind_obj=KindObject.event,
                uuid_user=user.uuid,
                uuid_obj=event.uuid,
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def get_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: args.PathUUIDEvent,
        tree: args.QueryTree = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            _, event = cls.verify_access(session, token, uuid_event)
            if tree:
                while uuid_parent := event.uuid_parent:
                    event = Event.if_exists(session, uuid_parent)

            return EventSchema.model_validate(event)

    @classmethod
    async def get_events(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        param: EventSearchSchema = Depends(),
        flatten: args.QueryFlat = True,
        kind_recurse: args.QueryKindRecurse = KindRecurse.depth_first,
    ) -> List[EventWithRootSchema] | List[EventBaseSchema]:
        with sessionmaker() as session:
            User.if_exists(session, token["uuid"]).check_not_deleted()
            q = Event.q_select_search(token["uuid"], **param.model_dump())
            res = session.execute(q)
            uuid_event: Set[str] = set(res.scalars())

            if flatten:
                q = Event.q_select_recursive(
                    uuid_event,
                    kind_recurse=kind_recurse,
                ).order_by(Event.timestamp)
                events = session.execute(q)
                T = EventWithRootSchema
            else:
                q = Event.q_uuid(uuid_event).order_by(Event.timestamp)
                events = (session.execute(q)).scalars()
                T = EventBaseSchema

            return [T.model_validate(ee) for ee in events]

    ## TODO: Finish this later when time exists for it.
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

    @classmethod
    def get_event_objects(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: args.PathUUIDUser,
    ) -> List[EventWithRootSchema]:
        """Restore a deletion from an event."""

        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            ...

    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken,
        uuid_event: args.PathUUIDUser,
    ) -> Tuple[User, Event]:
        event = Event.if_exists(session, uuid_event)
        user = (
            User.if_exists(session, token["uuid"])
            .check_can_access_event(event)
            .check_not_deleted(410)
        )

        return user, event

    T = TypeVar("T")

    @classmethod
    def iter_eventobject(
        cls, session: Session, events: List[T]
    ) -> Generator[Tuple[T, AnyModel], None, None]:
        for item in events:
            tt = Tables[item.kind_obj].value
            qq = select(tt).where(tt.uuid == item.uuid_obj)
            oo = session.execute(qq).scalar()
            if oo is None:
                continue
            yield item, oo

    @classmethod
    def patch_undo_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: args.PathUUIDUser,
    ) -> EventActionSchema:
        """Restore a deletion from an event.

        Return the events and updated objects.

        :param dry_run:
        """

        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            event.check_kind(KindEvent.delete).check_not_undone()

            # Event for restoring from event.

            event_root = event.find_root().check_kind(KindEvent.delete)
            event_root = event_root.check_not_undone()

            user.check_can_access_event(event_root).check_not_deleted(410)

            event_action = event_root.undone(
                api_version=__version__,
                api_origin="PATCH /events/restore/<uuid>",
                detail="Restored from deletion event.",
                uuid_user=token["uuid"],
            )
            session.add(event_action)

            for item in event.flattened():
                object_ = item.object_
                print(object_)
                if not hasattr(object_, "deleted"):
                    continue
                object_.deleted = False
                session.add(object_)

            session.commit()
            session.refresh(event_action)

            return EventActionSchema.model_validate(
                dict(event_action=event_action, event_root=event_root)
            )

    @classmethod
    def patch_undo_object(cls): ...
