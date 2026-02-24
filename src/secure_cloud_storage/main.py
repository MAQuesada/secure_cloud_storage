"""Entry point for the application: CLI (default) or Streamlit UI (--ui)."""

import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def main() -> None:
    """Run CLI or Streamlit UI. Use --ui to start the web interface."""
    if "--ui" in sys.argv:
        sys.argv.remove("--ui")
        # Run Streamlit app programmatically
        app_path = Path(__file__).resolve().parent / "ui" / "app.py"
        sys.argv = ["streamlit", "run", str(app_path), "--server.headless", "true"]
        import streamlit.web.cli as stcli

        stcli.main()
    else:
        from secure_cloud_storage.cli.main import cli

        cli()


if __name__ == "__main__":
    main()
