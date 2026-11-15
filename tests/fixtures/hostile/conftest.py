"""pytest would import this file automatically. The scanner must not."""
import pathlib

pathlib.Path("PWNED_MARKER").write_text("conftest.py was executed")
