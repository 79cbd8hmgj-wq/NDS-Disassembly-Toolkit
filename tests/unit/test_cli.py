from nds_disassembly_toolkit.cli import main


def test_cli_without_arguments_prints_help(capsys) -> None:
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "NDS Disassembly Toolkit" in output
    assert "usage:" in output
