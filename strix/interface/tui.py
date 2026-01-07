import argparse
import asyncio
import atexit
import logging
import random
import signal
import sys
import threading
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import TYPE_CHECKING, Any, ClassVar


if TYPE_CHECKING:
    from textual.timer import Timer

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.spinner import SPINNERS
from rich.style import Style
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, TextArea, Tree
from textual.widgets.tree import TreeNode

from strix.agents.StrixAgent import StrixAgent
from strix.interface.utils import build_live_stats_text
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer, set_global_tracer


def get_package_version() -> str:
    try:
        return pkg_version("strix-agent")
    except PackageNotFoundError:
        return "dev"


class ChatTextArea(TextArea):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_reference: StrixTUIApp | None = None

    def set_app_reference(self, app: "StrixTUIApp") -> None:
        self._app_reference = app

    def on_mount(self) -> None:
        self._update_height()

    def _on_key(self, event: events.Key) -> None:
        if event.key == "shift+enter":
            self.insert("\n")
            event.prevent_default()
            return

        if event.key == "enter" and self._app_reference:
            text_content = str(self.text)  # type: ignore[has-type]
            message = text_content.strip()
            if message:
                self.text = ""

                self._app_reference._send_user_message(message)

                event.prevent_default()
                return

        super()._on_key(event)

    @on(TextArea.Changed)  # type: ignore[misc]
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return

        line_count = self.document.line_count
        target_lines = min(max(1, line_count), 8)

        new_height = target_lines + 2

        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class SplashScreen(Static):  # type: ignore[misc]
    PRIMARY_GREEN = "#22c55e"
    BANNER = (
        " ███████╗████████╗██████╗ ██╗██╗  ██╗\n"
        " ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝\n"
        " ███████╗   ██║   ██████╔╝██║ ╚███╔╝\n"
        " ╚════██║   ██║   ██╔══██╗██║ ██╔██╗\n"
        " ███████║   ██║   ██║  ██║██║██╔╝ ██╗\n"
        " ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer: Timer | None = None
        self._panel_static: Static | None = None
        self._version = "dev"

    def compose(self) -> ComposeResult:
        self._version = get_package_version()
        self._animation_step = 0
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)

        panel_static = Static(panel, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return

        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        content = Group(
            Align.center(Text(self.BANNER.strip("\n"), style=self.PRIMARY_GREEN, justify="center")),
            Align.center(Text(" ")),
            Align.center(self._build_welcome_text()),
            Align.center(self._build_version_text()),
            Align.center(self._build_tagline_text()),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
            Align.center(Text(" ")),
            Align.center(self._build_url_text()),
        )

        return Panel.fit(content, border_style=self.PRIMARY_GREEN, padding=(1, 6))

    def _build_url_text(self) -> Text:
        return Text("strix.ai", style=Style(color=self.PRIMARY_GREEN, bold=True))

    def _build_welcome_text(self) -> Text:
        text = Text("Welcome to ", style=Style(color="white", bold=True))
        text.append("Strix", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append("!", style=Style(color="white", bold=True))
        return text

    def _build_version_text(self) -> Text:
        return Text(f"v{self._version}", style=Style(color="white", dim=True))

    def _build_tagline_text(self) -> Text:
        return Text("Open-source AI hackers for your apps", style=Style(color="white", dim=True))

    def _build_start_line_text(self, phase: int) -> Text:
        full_text = "Starting Strix Agent"
        text_len = len(full_text)

        shine_pos = phase % (text_len + 8)

        text = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)

            if dist <= 1:
                style = Style(color="bright_white", bold=True)
            elif dist <= 3:
                style = Style(color="white", bold=True)
            elif dist <= 5:
                style = Style(color="#a3a3a3")
            else:
                style = Style(color="#525252")

            text.append(char, style=style)

        return text


class HelpScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("🦉 Strix Help", id="help_title"),
            Label(
                "F1        Help\nCtrl+Q/C  Quit\nESC       Stop Agent\n"
                "Enter     Send message to agent\nTab       Switch panels\n↑/↓       Navigate tree",
                id="help_content",
            ),
            id="dialog",
        )

    def on_key(self, _event: events.Key) -> None:
        self.app.pop_screen()


class StopAgentScreen(ModalScreen):  # type: ignore[misc]
    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"🛑 Stop '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("Yes", variant="error", id="stop_agent"),
                Button("No", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel_stop", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "stop_agent":
                cancel_button = self.query_one("#cancel_stop", Button)
                cancel_button.focus()
            else:
                stop_button = self.query_one("#stop_agent", Button)
                stop_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)
        else:
            self.app.pop_screen()


class QuitScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Quit Strix?", id="quit_title"),
            Grid(
                Button("Yes", variant="error", id="quit"),
                Button("No", variant="default", id="cancel"),
                id="quit_buttons",
            ),
            id="quit_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "quit":
                cancel_button = self.query_one("#cancel", Button)
                cancel_button.focus()
            else:
                quit_button = self.query_one("#quit", Button)
                quit_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.app.action_custom_quit()
        else:
            self.app.pop_screen()


class StrixTUIApp(App):  # type: ignore[misc]
    CSS_PATH = "assets/tui_styles.tcss"

    SIDEBAR_MIN_WIDTH = 100

    selected_agent_id: reactive[str | None] = reactive(default=None)
    show_splash: reactive[bool] = reactive(default=True)

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "Help", priority=True),
        Binding("ctrl+q", "request_quit", "Quit", priority=True),
        Binding("ctrl+c", "request_quit", "Quit", priority=True),
        Binding("escape", "stop_selected_agent", "Stop Agent", priority=True),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.scan_config = self._build_scan_config(args)
        self.agent_config = self._build_agent_config(args)

        self.tracer = Tracer(self.scan_config["run_name"])
        self.tracer.set_scan_config(self.scan_config)
        set_global_tracer(self.tracer)

        self.agent_nodes: dict[str, TreeNode] = {}

        self._displayed_agents: set[str] = set()
        self._displayed_events: list[str] = []

        self._scan_thread: threading.Thread | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()

        self._action_verbs = [
            "Generating",
            "Scanning",
            "Analyzing",
            "Hacking",
            "Testing",
            "Exploiting",
            "Pwning",
            "Loading",
            "Running",
            "Working",
            "Strixing",
            "Thinking",
            "Reasoning",
        ]
        self._agent_verbs: dict[str, str] = {}  # agent_id -> current_verb
        self._agent_verb_timers: dict[str, Any] = {}  # agent_id -> timer
        self._spinner_frame_index: int = 0  # Current spinner frame index
        self._spinner_frames: list[str] = list(SPINNERS["dots"]["frames"])  # Braille spinner frames
        self._dot_animation_timer: Any | None = None

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "scan_id": args.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": args.run_name,
        }

    def _build_agent_config(self, args: argparse.Namespace) -> dict[str, Any]:
        scan_mode = getattr(args, "scan_mode", "deep")
        llm_config = LLMConfig(scan_mode=scan_mode)

        config = {
            "llm_config": llm_config,
            "max_iterations": 300,
        }

        if getattr(args, "local_sources", None):
            config["local_sources"] = args.local_sources

        return config

    def _setup_cleanup_handlers(self) -> None:
        def cleanup_on_exit() -> None:
            self.tracer.cleanup()

        def signal_handler(_signum: int, _frame: Any) -> None:
            self.tracer.cleanup()
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def compose(self) -> ComposeResult:
        if self.show_splash:
            yield SplashScreen(id="splash_screen")

    def watch_show_splash(self, show_splash: bool) -> None:
        if not show_splash and self.is_mounted:
            try:
                splash = self.query_one("#splash_screen")
                splash.remove()
            except ValueError:
                pass

            main_container = Vertical(id="main_container")

            self.mount(main_container)

            content_container = Horizontal(id="content_container")
            main_container.mount(content_container)

            chat_area_container = Vertical(id="chat_area_container")

            chat_display = Static("", id="chat_display")
            chat_history = VerticalScroll(chat_display, id="chat_history")
            chat_history.can_focus = True

            status_text = Static("", id="status_text")
            keymap_indicator = Static("", id="keymap_indicator")

            agent_status_display = Horizontal(
                status_text, keymap_indicator, id="agent_status_display", classes="hidden"
            )

            chat_prompt = Static("> ", id="chat_prompt")
            chat_input = ChatTextArea(
                "",
                id="chat_input",
                show_line_numbers=False,
            )
            chat_input.set_app_reference(self)
            chat_input_container = Horizontal(chat_prompt, chat_input, id="chat_input_container")

            agents_tree = Tree("🤖 Active Agents", id="agents_tree")
            agents_tree.root.expand()
            agents_tree.show_root = False

            agents_tree.show_guide = True
            agents_tree.guide_depth = 3
            agents_tree.guide_style = "dashed"

            stats_display = Static("", id="stats_display")

            sidebar = Vertical(agents_tree, stats_display, id="sidebar")

            content_container.mount(chat_area_container)
            content_container.mount(sidebar)

            chat_area_container.mount(chat_history)
            chat_area_container.mount(agent_status_display)
            chat_area_container.mount(chat_input_container)

            self.call_after_refresh(self._focus_chat_input)

    def _focus_chat_input(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            chat_input = self.query_one("#chat_input", ChatTextArea)
            chat_input.show_vertical_scrollbar = False
            chat_input.show_horizontal_scrollbar = False
            chat_input.focus()
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_chat_input)

    def _focus_agents_tree(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.focus()

            if agents_tree.root.children:
                first_node = agents_tree.root.children[0]
                agents_tree.select_node(first_node)
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_agents_tree)

    def on_mount(self) -> None:
        self.title = "strix"

        self.set_timer(4.5, self._hide_splash_screen)

    def _hide_splash_screen(self) -> None:
        self.show_splash = False

        self._start_scan_thread()

        self.set_interval(0.25, self._update_ui_from_tracer)

    def _update_ui_from_tracer(self) -> None:
        if self.show_splash:
            return

        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
            agents_tree = self.query_one("#agents_tree", Tree)

            if not self._is_widget_safe(chat_history) or not self._is_widget_safe(agents_tree):
                return
        except (ValueError, Exception):
            return

        agent_updates = False
        for agent_id, agent_data in list(self.tracer.agents.items()):
            if agent_id not in self._displayed_agents:
                self._add_agent_node(agent_data)
                self._displayed_agents.add(agent_id)
                agent_updates = True
            elif self._update_agent_node(agent_id, agent_data):
                agent_updates = True

        if agent_updates:
            self._expand_new_agent_nodes()

        self._update_chat_view()

        self._update_agent_status_display()

        self._update_stats_display()

    def _update_agent_node(self, agent_id: str, agent_data: dict[str, Any]) -> bool:
        if agent_id not in self.agent_nodes:
            return False

        try:
            agent_node = self.agent_nodes[agent_id]
            agent_name_raw = agent_data.get("name", "Agent")
            status = agent_data.get("status", "running")

            status_indicators = {
                "running": "🟢",
                "waiting": "⏸️",
                "completed": "✅",
                "failed": "❌",
                "stopped": "⏹️",
                "stopping": "⏸️",
                "llm_failed": "🔴",
            }

            status_icon = status_indicators.get(status, "🔵")
            vuln_count = self._agent_vulnerability_count(agent_id)
            vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
            agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

            if status == "running":
                self._start_agent_verb_timer(agent_id)
            elif status == "waiting":
                self._stop_agent_verb_timer(agent_id)
            else:
                self._stop_agent_verb_timer(agent_id)

            if agent_node.label != agent_name:
                agent_node.set_label(agent_name)
                return True

        except (KeyError, AttributeError, ValueError) as e:
            import logging

            logging.warning(f"Failed to update agent node label: {e}")

        return False

    def _get_chat_content(
        self,
    ) -> tuple[Text | None, str | None]:
        if not self.selected_agent_id:
            return self._get_chat_placeholder_content(
                "Select an agent from the tree to see its activity.", "placeholder-no-agent"
            )

        events = self._gather_agent_events(self.selected_agent_id)
        streaming = self.tracer.get_streaming_content(self.selected_agent_id)

        if not events and not streaming:
            return self._get_chat_placeholder_content(
                "Starting agent...", "placeholder-no-activity"
            )

        current_event_ids = [e["id"] for e in events]

        if not streaming and current_event_ids == self._displayed_events:
            return None, None

        self._displayed_events = current_event_ids
        return self._get_rendered_events_content(events), "chat-content"

    def _update_chat_view(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash or not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(chat_history):
            return

        try:
            is_at_bottom = chat_history.scroll_y >= chat_history.max_scroll_y
        except (AttributeError, ValueError):
            is_at_bottom = True

        content, css_class = self._get_chat_content()
        if content is None:
            return

        chat_display = self.query_one("#chat_display", Static)
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class)

        if is_at_bottom:
            self.call_later(chat_history.scroll_end, animate=False)

    def _get_chat_placeholder_content(
        self, message: str, placeholder_class: str
    ) -> tuple[Text, str]:
        self._displayed_events = [placeholder_class]
        text = Text()
        text.append(message)
        return text, f"chat-placeholder {placeholder_class}"

    def _get_rendered_events_content(self, events: list[dict[str, Any]]) -> Text:
        result = Text()

        if not events:
            return result

        first = True
        for event in events:
            content: Text | None = None

            if event["type"] == "chat":
                content = self._render_chat_content(event["data"])
            elif event["type"] == "tool":
                content = self._render_tool_content_simple(event["data"])

            if content:
                if not first:
                    result.append("\n\n")
                result.append_text(content)
                first = False

        if self.selected_agent_id:
            streaming = self.tracer.get_streaming_content(self.selected_agent_id)
            if streaming:
                streaming_text = self._render_streaming_content(streaming)
                if streaming_text:
                    if not first:
                        result.append("\n\n")
                    result.append_text(streaming_text)

        return result

    def _render_streaming_content(self, content: str) -> Text:
        from strix.interface.streaming_parser import parse_streaming_content

        result = Text()
        segments = parse_streaming_content(content)

        for i, segment in enumerate(segments):
            if i > 0:
                result.append("\n\n")

            if segment.type == "text":
                from strix.interface.tool_components.agent_message_renderer import (
                    AgentMessageRenderer,
                )

                text_content = AgentMessageRenderer.render_simple(segment.content)
                result.append_text(text_content)

            elif segment.type == "tool":
                tool_text = self._render_streaming_tool(
                    segment.tool_name or "unknown",
                    segment.args or {},
                    segment.is_complete,
                )
                result.append_text(tool_text)

        return result

    def _render_streaming_tool(
        self, tool_name: str, args: dict[str, str], is_complete: bool
    ) -> Text:
        from strix.interface.tool_components.registry import get_tool_renderer

        tool_data = {
            "tool_name": tool_name,
            "args": args,
            "status": "completed" if is_complete else "running",
            "result": None,
        }

        renderer = get_tool_renderer(tool_name)
        if renderer:
            widget = renderer.render(tool_data)
            renderable = widget.renderable
            if isinstance(renderable, Text):
                return renderable
            text = Text()
            text.append(str(renderable))
            return text

        return self._render_default_streaming_tool(tool_name, args, is_complete)

    def _render_default_streaming_tool(
        self, tool_name: str, args: dict[str, str], is_complete: bool
    ) -> Text:
        text = Text()

        if is_complete:
            text.append("✓ ", style="green")
        else:
            text.append("● ", style="yellow")

        text.append("Using tool ", style="dim")
        text.append(tool_name, style="bold blue")

        if args:
            for key, value in list(args.items())[:3]:
                text.append("\n  ")
                text.append(key, style="dim")
                text.append(": ")
                display_value = value if len(value) <= 100 else value[:97] + "..."
                text.append(display_value, style="italic" if not is_complete else None)

        return text

    def _get_status_display_content(
        self, agent_id: str, agent_data: dict[str, Any]
    ) -> tuple[Text | None, Text, bool]:
        status = agent_data.get("status", "running")

        def keymap_text(msg: str) -> Text:
            t = Text()
            t.append(msg, style="dim")
            return t

        simple_statuses: dict[str, tuple[str, str]] = {
            "stopping": ("Agent stopping...", ""),
            "stopped": ("Agent stopped", ""),
            "completed": ("Agent completed", ""),
        }

        if status in simple_statuses:
            msg, km = simple_statuses[status]
            text = Text()
            text.append(msg)
            return (text, keymap_text(km), False)

        if status == "llm_failed":
            error_msg = agent_data.get("error_message", "")
            text = Text()
            if error_msg:
                text.append(error_msg, style="red")
            else:
                text.append("LLM request failed", style="red")
            self._stop_dot_animation()
            return (text, keymap_text("Send message to retry"), False)

        if status == "waiting":
            animated_text = self._get_animated_waiting_text(agent_id)
            return (animated_text, keymap_text("Send message to resume"), True)

        if status == "running":
            verb = (
                self._get_agent_verb(agent_id)
                if self._agent_has_real_activity(agent_id)
                else "Initializing Agent"
            )
            animated_text = self._get_animated_verb_text(agent_id, verb)
            return (animated_text, keymap_text("ESC to stop | CTRL-C to quit and save"), True)

        return (None, Text(), False)

    def _update_agent_status_display(self) -> None:
        try:
            status_display = self.query_one("#agent_status_display", Horizontal)
            status_text = self.query_one("#status_text", Static)
            keymap_indicator = self.query_one("#keymap_indicator", Static)
        except (ValueError, Exception):
            return

        widgets = [status_display, status_text, keymap_indicator]
        if not all(self._is_widget_safe(w) for w in widgets):
            return

        if not self.selected_agent_id:
            self._safe_widget_operation(status_display.add_class, "hidden")
            return

        try:
            agent_data = self.tracer.agents[self.selected_agent_id]
            content, keymap, should_animate = self._get_status_display_content(
                self.selected_agent_id, agent_data
            )

            if not content:
                self._safe_widget_operation(status_display.add_class, "hidden")
                return

            self._safe_widget_operation(status_text.update, content)
            self._safe_widget_operation(keymap_indicator.update, keymap)
            self._safe_widget_operation(status_display.remove_class, "hidden")

            if should_animate:
                self._start_dot_animation()

        except (KeyError, Exception):
            self._safe_widget_operation(status_display.add_class, "hidden")

    def _update_stats_display(self) -> None:
        try:
            stats_display = self.query_one("#stats_display", Static)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(stats_display):
            return

        stats_content = Text()

        stats_text = build_live_stats_text(self.tracer, self.agent_config)
        if stats_text:
            stats_content.append(stats_text)

        from rich.panel import Panel

        stats_panel = Panel(
            stats_content,
            border_style="#333333",
            padding=(0, 1),
        )

        self._safe_widget_operation(stats_display.update, stats_panel)

    def _get_agent_verb(self, agent_id: str) -> str:
        if agent_id not in self._agent_verbs:
            self._agent_verbs[agent_id] = random.choice(self._action_verbs)  # nosec B311 # noqa: S311
        return self._agent_verbs[agent_id]

    def _start_agent_verb_timer(self, agent_id: str) -> None:
        if agent_id not in self._agent_verb_timers:
            self._agent_verb_timers[agent_id] = self.set_interval(
                30.0, lambda: self._change_agent_action_verb(agent_id)
            )

    def _stop_agent_verb_timer(self, agent_id: str) -> None:
        if agent_id in self._agent_verb_timers:
            self._agent_verb_timers[agent_id].stop()
            del self._agent_verb_timers[agent_id]

    def _change_agent_action_verb(self, agent_id: str) -> None:
        if agent_id not in self._agent_verbs:
            self._agent_verbs[agent_id] = random.choice(self._action_verbs)  # nosec B311 # noqa: S311
            return

        current_verb = self._agent_verbs[agent_id]
        available_verbs = [verb for verb in self._action_verbs if verb != current_verb]
        self._agent_verbs[agent_id] = random.choice(available_verbs)  # nosec B311 # noqa: S311

        if self.selected_agent_id == agent_id:
            self._update_agent_status_display()

    def _get_animated_verb_text(self, agent_id: str, verb: str) -> Text:  # noqa: ARG002
        text = Text()
        spinner_char = self._spinner_frames[self._spinner_frame_index % len(self._spinner_frames)]
        text.append(spinner_char, style=Style(color="#22c55e"))
        text.append(" ", style=Style(color="white"))
        text.append(verb, style=Style(color="white"))
        return text

    def _get_animated_waiting_text(self, agent_id: str) -> Text:  # noqa: ARG002
        text = Text()
        spinner_char = self._spinner_frames[self._spinner_frame_index % len(self._spinner_frames)]
        text.append(spinner_char, style=Style(color="#fbbf24"))
        text.append(" ", style=Style(color="white"))
        text.append("Waiting", style=Style(color="#fbbf24"))
        return text

    def _start_dot_animation(self) -> None:
        if self._dot_animation_timer is None:
            self._dot_animation_timer = self.set_interval(0.05, self._animate_dots)

    def _stop_dot_animation(self) -> None:
        if self._dot_animation_timer is not None:
            self._dot_animation_timer.stop()
            self._dot_animation_timer = None

    def _animate_dots(self) -> None:
        has_active_agents = False

        if self.selected_agent_id and self.selected_agent_id in self.tracer.agents:
            agent_data = self.tracer.agents[self.selected_agent_id]
            status = agent_data.get("status", "running")
            if status in ["running", "waiting"]:
                has_active_agents = True
                self._spinner_frame_index = (self._spinner_frame_index + 1) % len(
                    self._spinner_frames
                )
                self._update_agent_status_display()

        if not has_active_agents:
            has_active_agents = any(
                agent_data.get("status", "running") in ["running", "waiting"]
                for agent_data in self.tracer.agents.values()
            )

        if not has_active_agents:
            self._stop_dot_animation()
            self._spinner_frame_index = 0

    def _agent_has_real_activity(self, agent_id: str) -> bool:
        initial_tools = {"scan_start_info", "subagent_start_info"}

        for _exec_id, tool_data in list(self.tracer.tool_executions.items()):
            if tool_data.get("agent_id") == agent_id:
                tool_name = tool_data.get("tool_name", "")
                if tool_name not in initial_tools:
                    return True
        return False

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        count = 0
        for _exec_id, tool_data in list(self.tracer.tool_executions.items()):
            if tool_data.get("agent_id") == agent_id:
                tool_name = tool_data.get("tool_name", "")
                if tool_name == "create_vulnerability_report":
                    status = tool_data.get("status", "")
                    if status == "completed":
                        result = tool_data.get("result", {})
                        if isinstance(result, dict) and result.get("success"):
                            count += 1
        return count

    def _gather_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        chat_events = [
            {
                "type": "chat",
                "timestamp": msg["timestamp"],
                "id": f"chat_{msg['message_id']}",
                "data": msg,
            }
            for msg in self.tracer.chat_messages
            if msg.get("agent_id") == agent_id
        ]

        tool_events = [
            {
                "type": "tool",
                "timestamp": tool_data["timestamp"],
                "id": f"tool_{exec_id}",
                "data": tool_data,
            }
            for exec_id, tool_data in list(self.tracer.tool_executions.items())
            if tool_data.get("agent_id") == agent_id
        ]

        events = chat_events + tool_events
        events.sort(key=lambda e: (e["timestamp"], e["id"]))
        return events

    def watch_selected_agent_id(self, _agent_id: str | None) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        self._displayed_events.clear()

        self.call_later(self._update_chat_view)
        self._update_agent_status_display()

    def _start_scan_thread(self) -> None:
        def scan_target() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                try:
                    agent = StrixAgent(self.agent_config)

                    if not self._scan_stop_event.is_set():
                        loop.run_until_complete(agent.execute_scan(self.scan_config))

                except (KeyboardInterrupt, asyncio.CancelledError):
                    logging.info("Scan interrupted by user")
                except (ConnectionError, TimeoutError):
                    logging.exception("Network error during scan")
                except RuntimeError:
                    logging.exception("Runtime error during scan")
                except Exception:
                    logging.exception("Unexpected error during scan")
                finally:
                    loop.close()
                    self._scan_completed.set()

            except Exception:
                logging.exception("Error setting up scan thread")
                self._scan_completed.set()

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    def _add_agent_node(self, agent_data: dict[str, Any]) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        agent_id = agent_data["id"]
        parent_id = agent_data.get("parent_id")
        status = agent_data.get("status", "running")

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return

        agent_name_raw = agent_data.get("name", "Agent")

        status_indicators = {
            "running": "🟢",
            "waiting": "🟡",
            "completed": "✅",
            "failed": "❌",
            "stopped": "⏹️",
            "stopping": "⏸️",
        }

        status_icon = status_indicators.get(status, "🔵")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        if status in ["running", "waiting"]:
            self._start_agent_verb_timer(agent_id)

        try:
            if parent_id and parent_id in self.agent_nodes:
                parent_node = self.agent_nodes[parent_id]
                agent_node = parent_node.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )
                parent_node.allow_expand = True
            else:
                agent_node = agents_tree.root.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )

            agent_node.allow_expand = False
            agent_node.expand()
            self.agent_nodes[agent_id] = agent_node

            if len(self.agent_nodes) == 1:
                agents_tree.select_node(agent_node)
                self.selected_agent_id = agent_id

            self._reorganize_orphaned_agents(agent_id)
        except (AttributeError, ValueError, RuntimeError) as e:
            import logging

            logging.warning(f"Failed to add agent node {agent_id}: {e}")

    def _expand_new_agent_nodes(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

    def _expand_all_agent_nodes(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            self._expand_node_recursively(agents_tree.root)
        except (ValueError, Exception):
            logging.debug("Tree not ready for expanding nodes")

    def _expand_node_recursively(self, node: TreeNode) -> None:
        if not node.is_expanded:
            node.expand()
        for child in node.children:
            self._expand_node_recursively(child)

    def _copy_node_under(self, node_to_copy: TreeNode, new_parent: TreeNode) -> None:
        agent_id = node_to_copy.data["agent_id"]
        agent_data = self.tracer.agents.get(agent_id, {})
        agent_name_raw = agent_data.get("name", "Agent")
        status = agent_data.get("status", "running")

        status_indicators = {
            "running": "🟢",
            "waiting": "🟡",
            "completed": "✅",
            "failed": "❌",
            "stopped": "⏹️",
            "stopping": "⏸️",
        }

        status_icon = status_indicators.get(status, "🔵")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        new_node = new_parent.add(
            agent_name,
            data=node_to_copy.data,
        )
        new_node.allow_expand = node_to_copy.allow_expand

        self.agent_nodes[agent_id] = new_node

        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)

        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        agents_to_move = []

        for agent_id, agent_data in list(self.tracer.agents.items()):
            if (
                agent_data.get("parent_id") == new_parent_id
                and agent_id in self.agent_nodes
                and agent_id != new_parent_id
            ):
                agents_to_move.append(agent_id)

        if not agents_to_move:
            return

        parent_node = self.agent_nodes[new_parent_id]

        for child_agent_id in agents_to_move:
            if child_agent_id in self.agent_nodes:
                old_node = self.agent_nodes[child_agent_id]

                if old_node.parent is parent_node:
                    continue

                self._copy_node_under(old_node, parent_node)

                old_node.remove()

        parent_node.allow_expand = True
        parent_node.expand()

    def _render_chat_content(self, msg_data: dict[str, Any]) -> Text | None:
        role = msg_data.get("role")
        content = msg_data.get("content", "")
        metadata = msg_data.get("metadata", {})

        if not content:
            return None

        if role == "user":
            from strix.interface.tool_components.user_message_renderer import UserMessageRenderer

            return UserMessageRenderer.render_simple(content)

        if metadata.get("interrupted"):
            result = self._render_streaming_content(content)
            result.append("\n")
            result.append("⚠ ", style="yellow")
            result.append("Interrupted by user", style="yellow dim")
            return result

        from strix.interface.tool_components.agent_message_renderer import AgentMessageRenderer

        return AgentMessageRenderer.render_simple(content)

    def _render_tool_content_simple(self, tool_data: dict[str, Any]) -> Text | None:
        tool_name = tool_data.get("tool_name", "Unknown Tool")
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        from strix.interface.tool_components.registry import get_tool_renderer

        renderer = get_tool_renderer(tool_name)

        if renderer:
            widget = renderer.render(tool_data)
            renderable = widget.renderable
            if isinstance(renderable, Text):
                return renderable
            text = Text()
            text.append(str(renderable))
            return text

        text = Text()

        if tool_name == "llm_error_details":
            text.append("✗ LLM Request Failed", style="red")
            if args.get("details"):
                details = str(args["details"])
                if len(details) > 300:
                    details = details[:297] + "..."
                text.append("\nDetails: ", style="dim")
                text.append(details)
            return text

        text.append("→ Using tool ")
        text.append(tool_name, style="bold blue")

        status_styles = {
            "running": ("●", "yellow"),
            "completed": ("✓", "green"),
            "failed": ("✗", "red"),
            "error": ("✗", "red"),
        }
        icon, style = status_styles.get(status, ("○", "dim"))
        text.append(" ")
        text.append(icon, style=style)

        if args:
            for k, v in list(args.items())[:2]:
                str_v = str(v)
                if len(str_v) > 80:
                    str_v = str_v[:77] + "..."
                text.append("\n  ")
                text.append(k, style="dim")
                text.append(": ")
                text.append(str_v)

        if status in ["completed", "failed", "error"] and result:
            result_str = str(result)
            if len(result_str) > 150:
                result_str = result_str[:147] + "..."
            text.append("\n")
            text.append("Result: ", style="bold")
            text.append(result_str)

        return text

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        node = event.node

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return

        if self.focused == agents_tree and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        node = event.node

        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def _send_user_message(self, message: str) -> None:
        if not self.selected_agent_id:
            return

        if self.tracer:
            streaming_content = self.tracer.get_streaming_content(self.selected_agent_id)
            if streaming_content and streaming_content.strip():
                self.tracer.clear_streaming_content(self.selected_agent_id)
                self.tracer.interrupted_content[self.selected_agent_id] = streaming_content
                self.tracer.log_chat_message(
                    content=streaming_content,
                    role="assistant",
                    agent_id=self.selected_agent_id,
                    metadata={"interrupted": True},
                )

        try:
            from strix.tools.agents_graph.agents_graph_actions import _agent_instances

            if self.selected_agent_id in _agent_instances:
                agent_instance = _agent_instances[self.selected_agent_id]
                if hasattr(agent_instance, "cancel_current_execution"):
                    agent_instance.cancel_current_execution()
        except (ImportError, AttributeError, KeyError):
            pass

        if self.tracer:
            self.tracer.log_chat_message(
                content=message,
                role="user",
                agent_id=self.selected_agent_id,
            )

        try:
            from strix.tools.agents_graph.agents_graph_actions import send_user_message_to_agent

            send_user_message_to_agent(self.selected_agent_id, message)

        except (ImportError, AttributeError) as e:
            import logging

            logging.warning(f"Failed to send message to agent {self.selected_agent_id}: {e}")

        self._displayed_events.clear()
        self._update_chat_view()

        self.call_after_refresh(self._focus_chat_input)

    def _get_agent_name(self, agent_id: str) -> str:
        try:
            if self.tracer and agent_id in self.tracer.agents:
                agent_name = self.tracer.agents[agent_id].get("name")
                if isinstance(agent_name, str):
                    return agent_name
        except (KeyError, AttributeError) as e:
            logging.warning(f"Could not retrieve agent name for {agent_id}: {e}")
        return "Unknown Agent"

    def action_toggle_help(self) -> None:
        if self.show_splash or not self.is_mounted:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return

        if len(self.screen_stack) > 1:
            return

        self.push_screen(HelpScreen())

    def action_request_quit(self) -> None:
        if self.show_splash or not self.is_mounted:
            self.action_custom_quit()
            return

        if len(self.screen_stack) > 1:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            self.action_custom_quit()
            return

        self.push_screen(QuitScreen())

    def action_stop_selected_agent(self) -> None:
        if (
            self.show_splash
            or not self.is_mounted
            or len(self.screen_stack) > 1
            or not self.selected_agent_id
        ):
            return

        agent_name, should_stop = self._validate_agent_for_stopping()
        if not should_stop:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        self.push_screen(StopAgentScreen(agent_name, self.selected_agent_id))

    def _validate_agent_for_stopping(self) -> tuple[str, bool]:
        agent_name = "Unknown Agent"

        try:
            if self.tracer and self.selected_agent_id in self.tracer.agents:
                agent_data = self.tracer.agents[self.selected_agent_id]
                agent_name = agent_data.get("name", "Unknown Agent")

                agent_status = agent_data.get("status", "running")
                if agent_status not in ["running"]:
                    return agent_name, False

                agent_events = self._gather_agent_events(self.selected_agent_id)
                if not agent_events:
                    return agent_name, False

                return agent_name, True

        except (KeyError, AttributeError, ValueError) as e:
            import logging

            logging.warning(f"Failed to gather agent events: {e}")

        return agent_name, False

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        self.pop_screen()

        try:
            from strix.tools.agents_graph.agents_graph_actions import stop_agent

            result = stop_agent(agent_id)

            import logging

            if result.get("success"):
                logging.info(f"Stop request sent to agent: {result.get('message', 'Unknown')}")
            else:
                logging.warning(f"Failed to stop agent: {result.get('error', 'Unknown error')}")

        except Exception:
            import logging

            logging.exception(f"Failed to stop agent {agent_id}")

    def action_custom_quit(self) -> None:
        for agent_id in list(self._agent_verb_timers.keys()):
            self._stop_agent_verb_timer(agent_id)

        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_stop_event.set()

            self._scan_thread.join(timeout=1.0)

        self.tracer.cleanup()

        self.exit()

    def _is_widget_safe(self, widget: Any) -> bool:
        try:
            _ = widget.screen
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return bool(widget.is_mounted)

    def _safe_widget_operation(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> bool:
        try:
            operation(*args, **kwargs)
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return True

    def on_resize(self, event: events.Resize) -> None:
        if self.show_splash or not self.is_mounted:
            return

        try:
            sidebar = self.query_one("#sidebar", Vertical)
            chat_area = self.query_one("#chat_area_container", Vertical)
        except (ValueError, Exception):
            return

        if event.size.width < self.SIDEBAR_MIN_WIDTH:
            sidebar.add_class("-hidden")
            chat_area.add_class("-full-width")
        else:
            sidebar.remove_class("-hidden")
            chat_area.remove_class("-full-width")


async def run_tui(args: argparse.Namespace) -> None:
    """Run strix in interactive TUI mode with textual."""
    app = StrixTUIApp(args)
    await app.run_async()
