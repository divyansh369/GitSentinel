import typer, os
from pathlib import Path
from .scanners.secret_detector import scan_file

app = typer.Typer()


@app.command()
def scan(directory_path: str = typer.Argument(..., help="Directory to scan")):
    path = Path(directory_path)

    if not path.exists():
        typer.echo(f" Error: Path '{directory_path}' does not exist.")
        raise typer.Exit(code=1)

    typer.echo(f"Scanning started in: {path.absolute()}")


    for file_path in path.rglob("*"):
        if file_path.is_file() and ".git" not in file_path.parts:
            finding = scan_file(file_path)
            typer.echo(finding)

@app.command()
def version():
    typer.echo("gitsentinel v0.1.0")


if __name__ == "__main__":
    app()
