import os
from pathlib import Path
import pytest

LAB_DIR = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def chdir_to_lab():
    """Pin CWD to the lab directory for every test.

    Tests use Path("logs/exfil/exfil.log") and subprocess calls like
    ["python3", "agent.py", ...] — both require CWD to be the lab root.
    """
    old = os.getcwd()
    os.chdir(LAB_DIR)
    yield
    os.chdir(old)
