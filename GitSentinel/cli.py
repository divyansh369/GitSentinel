import typer
import json
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.table import Table

from .scanners.secret_detector import scan_file

console = Console()
app = typer.Typer(help="GitSentinel: A fast and lightweight secret scanner.")

# Severity ranking for easy comparison
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def create_report_table(findings: List[dict], title: str) -> Table:
    """Creates a formatted Rich table for findings."""
    table = Table(title=f"\n {title}")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="yellow", justify="center")
    table.add_column("Issue", style="white")
    table.add_column("Severity", style="bold")

    for f in findings:
        sev = f["severity"].lower()
        color = "red" if sev == "high" else "yellow" if sev == "medium" else "blue"

        table.add_row(
            f["filename"],
            str(f["line"]),
            f["message"],
            f"[{color}]{f['severity']}[/{color}]",
        )
    return table


@app.command()
def scan(
    directory_path: str = typer.Argument(..., help="Directory to scan"),
    min_severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Min severity: low, medium, high"
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o", help="Format: terminal, json"
    ),
):
    path = Path(directory_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Path '{directory_path}' not found.")
        raise typer.Exit(1)

    all_findings = []

    # 1. Data Collection Phase
    with console.status("[bold green]Scanning files...[/bold green]"):
        for file_path in path.rglob("*"):
            if file_path.is_file() and ".git" not in file_path.parts:
                file_results = scan_file(file_path)

                for f in file_results:
                    f_sev = f["severity"].lower()

                    # Filtering Logic
                    if min_severity:
                        if SEVERITY_ORDER.get(f_sev, 0) < SEVERITY_ORDER.get(
                            min_severity.lower(), 0
                        ):
                            continue

                    all_findings.append(f)

    if not all_findings:
        console.print("[bold green]✅ No issues found![/bold green]")
        return

    if output.lower() == "json":
        output_file = "gitsentinel_report.json"
        with open(output_file, "w") as f:
            json.dump(all_findings, f, indent=4)
        console.print(f"[bold cyan] Report saved to {output_file}[/bold cyan]")
    else:
        report_table = create_report_table(
            all_findings, f"GitSentinel Scan Report: {path.name}"
        )
        console.print(report_table)


@app.command()
def version():
    """Display the current version."""
    console.print("[bold blue]GitSentinel v0.1.0[/bold blue]")


if __name__ == "__main__":
    app()
