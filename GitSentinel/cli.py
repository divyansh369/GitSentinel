import typer

app = typer.Typer()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Directory to scan"),
):
    typer.echo(f"Scanning {path}...")


@app.command()
def version():
    typer.echo("gitsentinel v0.1.0")


if __name__ == "__main__":
    app()
