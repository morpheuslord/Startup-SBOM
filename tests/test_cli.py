import pytest
import sys
from unittest.mock import patch
from sbom_cli.main import main

def test_cli_help(capsys):
    # Simulate --help argument
    with patch.object(sys, "argv", ["main.py", "--help"]):
        with pytest.raises(SystemExit) as e:
            main()
        
        # Check exit code 0 (success for help)
        assert e.value.code == 0
        
        # Check output contains description
        captured = capsys.readouterr()
        assert "STARTUP SBOM" in captured.out
