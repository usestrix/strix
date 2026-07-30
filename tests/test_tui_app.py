from unittest.mock import MagicMock

from strix.interface.tui.app import SdkStreamEvent, StrixTUIApp


def test_capture_sdk_event_posts_without_waiting_for_ui_thread() -> None:
    app = MagicMock(spec=StrixTUIApp)
    event = object()

    StrixTUIApp._capture_sdk_event(app, "agent-1", event)

    app.post_message.assert_called_once()
    message = app.post_message.call_args.args[0]
    assert isinstance(message, SdkStreamEvent)
    assert message.agent_id == "agent-1"
    assert message.event is event
    app.call_from_thread.assert_not_called()
    app._record_sdk_event.assert_not_called()


def test_sdk_stream_event_is_recorded_on_ui_thread() -> None:
    app = MagicMock(spec=StrixTUIApp)
    event = object()

    StrixTUIApp._on_sdk_stream_event(app, SdkStreamEvent("agent-1", event))

    app._record_sdk_event.assert_called_once_with("agent-1", event)
