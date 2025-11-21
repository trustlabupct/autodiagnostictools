"""Module entry point for `python -m trustmitre`."""

from .cli import app


def main() -> None:
    """Invoke the Typer application."""
    app()


if __name__ == "__main__":
    main()
