# =========================================================================== #
from typing import Self, Tuple

from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from captura.fields import KindObject
from captura.models import AnyModel, Resolvable, resolve_model


class Check:
    session: Session

    def __init__(self, session: Session):
        self.session = session

    def uuids(
        self,
        kind_obj: KindObject,
        objs_expect: Resolvable,
        objs: Resolvable,
    ) -> Self:
        M = resolve_model(kind_obj)
        assert M.resolve_uuid(self.session, objs_expect) == M.resolve_uuid(
            self.session, objs
        )
        return self

    def all_(self, objs: Tuple[AnyModel, ...], **fields) -> Self:
        n = len(objs)
        fmt = f"`{{}}/{n}` unexpected values for field `{{}}`. Values = `{{}}`, test = {{}}"
        for field_name, field_value in fields.items():
            if callable(field_value):
                bad = tuple(
                    getattr(obj, field_name) for obj in objs if field_value(obj)
                )
            else:
                bad = tuple(
                    attr
                    for obj in objs
                    if (attr := getattr(obj, field_name)) != field_value
                )

            msg = fmt.format(n_bad := len(bad), field_name, bad, field_value)
            assert not n_bad, msg

        return self
