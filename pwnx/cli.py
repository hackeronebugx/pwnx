"""Rich-powered CLI entry point."""

import click
import asyncio
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from pwnx.core.engine import hunt_xss
from pwnx.config import XSSGAI_DIR

console = Console()

@click.command()
@click.option("--target", required=True, help="Target URL to scan")
@click.option("--selector", default="heuristic", type=click.Choice(["heuristic", "groq", "ollama"]), help="AI selector mode")
@click.option("--xssgai", is_flag=True, help="Enable XSSGAI payload generation")
@click.option("--headless", is_flag=True, help="Enable headless browser confirmation")
@click.option("--output", default=None, help="Output file for report")
@click.option("--verbose", is_flag=True, help="Verbose output")
def main(target, selector, xssgai, headless, output, verbose):
    """PwnX - AI-Augmented XSS Hunter"""

    banner = Text()
    banner.append("╔═══════════════════════════════════════\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("PwnX", style="bold red")
    banner.append(" v2.0.0", style="bold yellow")
    banner.append("                    ║\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("AI-Augmented XSS Hunter", style="dim")
    banner.append("       ║\n", style="bold cyan")
    banner.append("╚═══════════════════════════════════════", style="bold cyan")

    console.print(Panel(banner, border_style="cyan"))

    if xssgai and not XSSGAI_DIR:
        console.print("[yellow]⚠ XSSGAI enabled but XSSGAI_DIR not set. Falling back to database.[/yellow]")

    try:
        result = asyncio.run(hunt_xss(
            target=target,
            selector_mode=selector,
            use_xssgai=xssgai,
            headless=headless,
            verbose=verbose
        ))

        # Print summary
        total = result["summary"]["total_confirmed"]
        if total > 0:
            console.print(f"\n[bold green]✓ {total} XSS vector(s) confirmed[/bold green]")
            for finding in result.get("findings", []):
                if finding.get("success"):
                    for f in finding.get("findings", []):
                        console.print(f"  [green]• {f.get('param', finding.get('param'))}: {f.get('payload', 'N/A')[:50]}...[/green]")
                        console.print(f"    [dim]PoC: {f.get('poc_url', 'N/A')[:80]}...[/dim]")
        else:
            console.print("\n[bold yellow]✗ No XSS vectors confirmed[/bold yellow]")

        # Save report if requested
        if output:
            import json
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            console.print(f"\n[dim]Report saved to {output}[/dim]")

        # Always print full JSON for piping
        import json
        print("\n" + json.dumps(result, indent=2))

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise

if __name__ == "__main__":
    main()
