from typing import Any, Callable, Dict, Tuple, TypeAlias, TypeVar

import pytest
from fastapi import HTTPException


def check_exc(
    err: HTTPException,
    expected_status: int,
    *,
    check_length=True,
    **expected_detail: Any,
) -> AssertionError | None:

    if not expected_detail:
        raise ValueError("Expected `expected` to be non-empty.")

    msg: str
    detail: Dict[str, Any]
    match err:
        case HTTPException(detail=dict() as detail):
            detail = detail
        case HTTPException(detail=dict() as detail):
            return AssertionError(f"Detail missing `msg`. `{detail=}`.")
        case HTTPException(detail=_ as bad):
            msg = "Expected detail to be a dictionary."
            msg = f"{msg} Got `{bad=}` of type `{type(bad)}`."
            raise AssertionError(msg)
        case _ as detail:
            msg = f"Expected `AssertionError`, got `{type(detail)}`."
            raise AssertionError(msg)

    if (status := err.status_code) != expected_status:
        msg = f"Unexpected status code `{status}` for HTTPException."
        msg = f"{msg} Expected `{expected_status}`."
    elif check_length and (n := len(detail)) != (m := len(expected_detail)):
        msg = f"Expected detail to have length `{n}` but got `{m}`."
    elif missing_keys := set(key for key in expected_detail if key not in detail):
        msg = f"Detail missing `{missing_keys}`."
    elif bad_values := tuple(
        f"- {key}: {value_exp} -> {value}"
        for key, value_exp in expected_detail.items()
        if value_exp != (value := detail[key])
    ):

        lines = "  key: value_expected -> value\n"
        lines += "\n".join(bad_values)
        msg = "Detail has incorrect values:\n\n" + lines
    else:
        return None

    msg += f"\n`{detail=}`,\n`{expected_detail=}`."
    return AssertionError(msg)


CallableExpectExcIt: TypeAlias = Callable[[], Any]
CallableExpectExc: TypeAlias = Tuple[AssertionError | None, HTTPException]


def expect_exc(
    it: CallableExpectExcIt,
    expected_status: int,
    *,
    check_length=True,
    **expected,
) -> CallableExpectExc:

    with pytest.raises(HTTPException) as httperr:
        it()

    httperr = httperr.value
    err = check_exc(
        httperr,
        expected_status,
        check_length=check_length,
        **expected,
    )

    return err, httperr
