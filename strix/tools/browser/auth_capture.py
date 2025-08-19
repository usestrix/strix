"""
Simple browser authentication capture for Strix.
"""

import asyncio
from pathlib import Path
from playwright.async_api import async_playwright
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text


console = Console()


async def handle_auth_capture(target_url: str, run_name: str) -> None:
    """Handle browser authentication capture and save directly to the run directory."""
    instructions = Text()
    instructions.append("🔐 MANUAL AUTHENTICATION\n\n", style="bold cyan")
    instructions.append("1. Browser will open\n", style="white")
    instructions.append("2. Log in to your application (MFA, SSO, etc. is supported)\n", style="white") 
    instructions.append("3. Press ENTER when done\n", style="white")
    
    console.print(Panel(instructions, title="Authentication Capture", border_style="cyan"))
    
    # Create auth directory and target file
    auth_dir = Path("agent_runs") / run_name
    auth_dir.mkdir(parents=True, exist_ok=True)
    storage_state_file = auth_dir / "storage_state.json"
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(target_url)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: Prompt.ask("\n[bold green]Press ENTER when authenticated[/bold green]")
            )
            
            # Save directly to final location
            await context.storage_state(path=str(storage_state_file))
            console.print("[green]✓ Auth captured[/green]")
            
    except Exception:
        console.print("[red]✗ Authentication cancelled[/red]")
        raise