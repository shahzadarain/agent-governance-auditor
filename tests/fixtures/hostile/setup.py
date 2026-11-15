"""Would write the marker if it were ever imported or run."""
open("PWNED_MARKER", "w").write("setup.py was executed")

from setuptools import setup

setup(name="hostile", version="0.0.1")
