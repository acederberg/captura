# =========================================================================== #
from datetime import datetime

import httpx
import typer

# --------------------------------------------------------------------------- #
from captura.fields import KindObject, Singular
from legere import flags
from legere.flags import Output
from legere.handlers import CONSOLE, ConsoleHandler
from legere.requests.base import BaseRequests, ContextData, params

__all__ = ("EventsRequests",)


class EventsRequests(BaseRequests):
    typer_check_verbage = False
    typer_commands = dict(
        prune="req_prune",
        read="req_read",
        search="req_search",
        restore="req_restore",
        objects="req_objects",
    )

    def req_callback(
        cls,
        output: flags.FlagOutput = Output.yaml,
        columns: flags.FlagColumns = list(),
    ):
        """Specify request output format."""
        cls.output = output
        if not columns:
            columns = ["api_origin", "timestamp", "uuid_root"]
            columns += ["uuid_parent", "uuid", "kind", "kind_obj"]
            columns += ["uuid_obj", "detail"]
            cls.columns = columns

        # TODO: Fix this. Looks like events cli is probably broken.
        cls.handler = ConsoleHandler(output=output, columns=columns, data=None)  # type: ignore

    @classmethod
    def req_prune(
        cls,
        _context: typer.Context,
        kind_obj: flags.ArgKindObject,
        uuid_obj: flags.ArgUUIDEvent,
        *,
        root: bool = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        p = params(root=root)
        if kind_obj == KindObject.event:
            return httpx.Request(
                "DELETE", f"/events/{uuid_obj}", headers=context.headers, params=p
            )
        return httpx.Request(
            "DELETE",
            context.url(f"/events/{Singular(kind_obj.name).name}/{uuid_obj}"),
            headers=context.headers,
            params=p,
        )

    @classmethod
    def req_read(
        cls,
        _context: typer.Context,
        kind_obj: flags.ArgKindObject,
        uuid_obj: flags.ArgUUIDEvent,
        *,
        root: bool = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        if kind_obj == KindObject.event:
            return httpx.Request(
                "GET",
                context.url(f"/events/{uuid_obj}"),
                headers=context.headers,
                params=dict(root=root),
            )

        # NOTE: Across many controllers.
        kind_object_plural = Singular(kind_obj.name).name
        return httpx.Request(
            "GET",
            context.url(f"/{kind_object_plural}/{uuid_obj}/events"),
            params=params(root=root),
            headers=context.headers,
        )

    @classmethod
    def req_search(
        cls,
        # recurse: flags.FlagKindRecurse = KindRecurse.depth_firsut,
        # flatten: flags.FlagFlatten = True,
        _context: typer.Context,
        *,
        kind: flags.FlagKind = None,
        kind_obj: flags.FlagKindObjectOptional = None,
        uuid_obj: flags.FlagUUIDEventObjectOptional = None,
        uuid_event: flags.FlagUUIDEventsOptional = None,
        before: flags.FlagBefore = None,
        after: flags.FlagAfter = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        res = httpx.Request(
            "GET",
            context.url("/events"),
            headers=context.headers,
            params=(
                params(
                    # flatten=flatten,
                    # recurse=recurse.value if recurse is not None else None,
                    before=datetime.timestamp(before) if before is not None else before,
                    after=datetime.timestamp(after) if after is not None else after,
                    uuid_event=uuid_event,
                    uuid_obj=uuid_obj,
                    kind=kind.value if kind is not None else None,
                    kind_obj=kind_obj.value if kind_obj is not None else None,
                )
            ),
        )
        return res

    @classmethod
    def req_restore(
        cls,
        _context: typer.Context,
        *,
        uuid_object: flags.FlagUUIDEventObjectOptional = None,
        uuid_event: flags.FlagUUIDEventOptional = None,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        res = None
        match [uuid_object is None, uuid_event is None]:
            case [True, False]:
                res = httpx.Request(
                    "PATCH",
                    context.url(f"/events/{uuid_event}/objects"),
                    headers=context.headers,
                )
            case [False, True]:
                res = httpx.Request(
                    "PATCH",
                    context.url(f"/events/objects/{uuid_object}"),
                    headers=context.headers,
                )
            case [True, True] | [False | False] | _:
                CONSOLE.print(
                    "Exactly one of `--uuid-object` and `--uuid-event` must "
                    "be specified."
                )
                raise typer.Exit(1)

        return res

    @classmethod
    def req_objects(
        cls,
        _context: typer.Context,
        *,
        uuid_event: flags.ArgUUIDEvent,
        root: bool = False,
    ) -> httpx.Request:
        context = ContextData.resolve(_context)
        return httpx.Request(
            "GET",
            context.url(f"/events/{uuid_event}/objects"),
            params=params(root=root),
            headers=context.headers,
        )


if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    from legere.requests.base import typerize

    events = typerize(EventsRequests)
    events()
