from dash import Dash, Input, Output, callback, ctx, dcc, html

# --------------------------------------------------------------------------- #
from legere.requests.base import BaseTyperizable

# class BaseDashView:
#     ...
#
# class DashView:
#
#     ...
#
#
# class CommandDash(BaseTyperizable):
#
#     typer_commands = ...
#
#     @classmethod
#     def run(cls):
#         ...


app = Dash(__name__)
app.layout = html.Div(
    [
        html.H1(children="It works!"),
        html.P(
            children="",
            id=(input_display_id := "the_input_display"),
        ),
        dcc.Input("Write something here.", id=(input_id := "the_input")),
    ]
)


@callback(
    Output(input_display_id, "children"),
    Input(input_id, "value"),
)
def update_count(v: int) -> int:
    return v
