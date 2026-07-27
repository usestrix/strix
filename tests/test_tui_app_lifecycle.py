from types import SimpleNamespace
from typing import NoReturn

from strix.interface.tui.app import StrixTUIApp


def test_focus_chat_input_returns_when_app_is_not_running() -> None:
    scheduled_callbacks: list[object] = []

    def query_one(_selector: str, _widget_type: type[object]) -> NoReturn:
        raise ValueError("screen is not mounted")

    app = SimpleNamespace(
        screen_stack=[],
        show_splash=False,
        is_mounted=lambda _widget: False,
        is_running=False,
        query_one=query_one,
        call_after_refresh=scheduled_callbacks.append,
    )

    StrixTUIApp._focus_chat_input(app)  # type: ignore[arg-type]

    assert scheduled_callbacks == []
