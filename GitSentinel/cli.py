import typer, os
from pathlib import Path
from .scanners.secret_detector import scan_file
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer()


@app.command()
def scan(
    directory_path: str = typer.Argument(..., help="Directory to scan"),
    min_severity: str = typer.Option(
        None, "--severity", "-s", help="Filter results: low, medium, high"
    ),
):
    path = Path(directory_path)
    if not path.exists():
        console.print(
            f"[bold red]Error:[/bold red] Path '{directory_path}' does not exist."
        )
        raise typer.Exit(code=1)

    table = Table(title=f"🔍 GitSentinel Scan Report: {path.name}")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="yellow", justify="center")
    table.add_column("Issue", style="white")
    table.add_column("Severity", style="bold red")

    severity_order = {"low": 1, "medium": 2, "high": 3}
    found_any = False

    with console.status("[bold green]Scanning files...[/bold green]"):
        for file_path in path.rglob("*"):
            if file_path.is_file() and ".git" not in file_path.parts:
                findings = scan_file(file_path)

                for finding in findings:
                    f_sev = finding["severity"].lower()

                    # 2. Severity Filtering Logic
                    if min_severity:
                        target = min_severity.lower()
                        if severity_order.get(f_sev, 0) < severity_order.get(target, 0):
                            continue

                    issue = (
                        finding.get("message")
                        or f"High entropy: {finding.get('word')} (score: {finding.get('entropy')})"
                    )

                    sev_color = (
                        "red"
                        if f_sev == "high"
                        else "yellow" if f_sev == "medium" else "blue"
                    )

                    table.add_row(
                        finding["filename"],
                        str(finding["line"]),
                        issue,
                        f"[{sev_color}]{finding['severity']}[/{sev_color}]",
                    )
                    found_any = True

    if found_any:
        console.print(table)
    else:
        console.print(
            "[bold green]✅ No issues found with the selected severity![/bold green]"
        )


@app.command()
def version():
    typer.echo("gitsentinel v0.1.0")


if __name__ == "__main__":
    app()
