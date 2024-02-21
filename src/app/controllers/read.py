from http import HTTPMethod
from typing import Any, Dict, Generic, TypeVar

from app.token import Token
from app.controllers.access import Access, WithAccess
from app.controllers.base import Data, ResolvedUser
from sqlalchemy.orm import Session

T_ReadParam = TypeVar(
    "T_ReadParam",
)


class Read(WithAccess, Generic[T_ReadParam]):

    _read_data: T_ReadParam | None

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        read_data: T_ReadParam | None,
        *,
        detail: str,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
    ):
        if method != HTTPMethod.GET:
            raise ValueError("`method` must be `GET`.")

        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
            access=access,
        )
        self._read_data = read_data

    @property
    def read_data(self) -> T_ReadParam:
        if (read_data := self._read_data) is None:
            raise AttributeError("`read_data` is not yet set.")
        return read_data

    @read_data.setter
    def read_data(self, v: T_ReadParam):
        self._read_data = v

    def user(self, data: Data[ResolvedUser]) -> ...:
        ...


