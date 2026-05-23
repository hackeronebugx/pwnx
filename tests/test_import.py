"""Basic import test."""

def test_import():
    import pwnx
    assert pwnx.__version__ == "2.0.0"

def test_cli_import():
    from pwnx.cli import main
    assert callable(main)
