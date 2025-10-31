import atexit
import signal
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.agents.StrixAgent import StrixAgent
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer, set_global_tracer


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    start_text = Text()
    start_text.append("🦉 ", style="bold white")
    start_text.append("STRIX CYBERSECURITY AGENT", style="bold green")

    target_value = next(iter(args.target_dict.values())) if args.target_dict else args.target
    target_text = Text()
    target_text.append("🎯 Target: ", style="bold cyan")
    target_text.append(str(target_value), style="bold white")

    instructions_text = Text()
    if args.instruction:
        instructions_text.append("📋 Instructions: ", style="bold cyan")
        instructions_text.append(args.instruction, style="white")

    results_text = Text()
    results_text.append("📊 Results will be saved to: ", style="bold cyan")
    results_text.append(f"agent_runs/{args.run_name}", style="bold white")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("⏱️  ", style="dim")
    note_text.append("This may take a while depending on target complexity. ", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n" if args.instruction else "",
            instructions_text if args.instruction else "",
            "\n",
            results_text,
            note_text,
        ),
        title="[bold green]🛡️  STRIX PENETRATION TEST INITIATED",
        title_align="center",
        border_style="green",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    scan_config = {
        "scan_id": args.run_name,
        "scan_type": args.target_type,
        "target": args.target_dict,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
    }

    llm_config = LLMConfig()
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": 300,
        "non_interactive": True,
    }

    if args.target_type == "local_code" and "target_path" in args.target_dict:
        agent_config["local_source_path"] = args.target_dict["target_path"]
    elif args.target_type == "repository" and "cloned_repo_path" in args.target_dict:
        agent_config["local_source_path"] = args.target_dict["cloned_repo_path"]

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    def display_vulnerability(report_id: str, title: str, content: str, severity: str) -> None:
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#65a30d",
            "info": "#0284c7",
        }
        severity_color = severity_colors.get(severity.lower(), "#6b7280")

        vuln_text = Text()
        vuln_text.append("🐞 ", style="bold red")
        vuln_text.append("VULNERABILITY FOUND", style="bold red")
        vuln_text.append(" • ", style="dim white")
        vuln_text.append(title, style="bold white")

        severity_text = Text()
        severity_text.append("Severity: ", style="dim white")
        severity_text.append(severity.upper(), style=f"bold {severity_color}")

        vuln_panel = Panel(
            Text.assemble(
                vuln_text,
                "\n\n",
                severity_text,
                "\n\n",
                content,
            ),
            title=f"[bold red]🔍 {report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        tracer.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    try:
        console.print()
        with console.status("[bold cyan]Running penetration test...", spinner="dots") as status:
            agent = StrixAgent(agent_config)
            await agent.execute_scan(scan_config)
            status.stop()
    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("📄 ", style="bold cyan")
        final_report_text.append("FINAL PENETRATION TEST REPORT", style="bold cyan")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold cyan]📊 PENETRATION TEST SUMMARY",
            title_align="center",
            border_style="cyan",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
