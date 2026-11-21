import json

from inboxready import cli
from tests.test_checks import GOOD, fake


def run_cli(monkeypatch, capsys, argv):
    monkeypatch.setattr(cli, "make_lookup", lambda ns=None: fake(GOOD))
    code = cli.main(argv)
    return code, capsys.readouterr()


def test_text_output(monkeypatch, capsys):
    code, out = run_cli(monkeypatch, capsys, ["good.com"])
    assert code == 0 and "100/100" in out.out and "SPF" in out.out


def test_json_output(monkeypatch, capsys):
    code, out = run_cli(monkeypatch, capsys, ["good.com", "--json"])
    data = json.loads(out.out)
    assert data["grade"] == "A" and data["checks"][0]["name"] == "SPF"


def test_csv_and_min_score(monkeypatch, capsys):
    code, out = run_cli(monkeypatch, capsys, ["good.com", "bad-domain.com", "--csv", "--min-score", "80"])
    lines = out.out.strip().splitlines()
    assert lines[0].startswith("domain,score,grade") and len(lines) == 3
    assert code == 1  # bad-domain.com has no records


def test_file_input_and_dedupe(monkeypatch, capsys, tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("# my domains\ngood.com\nhttps://www.good.com\nbob@good.com\n")
    code, out = run_cli(monkeypatch, capsys, ["-f", str(f), "--json"])
    assert json.loads(out.out)["domain"] == "good.com"


def test_invalid_domain(monkeypatch, capsys):
    code, out = run_cli(monkeypatch, capsys, ["not a domain"])
    assert code == 2 and "not a valid domain" in out.err


def test_csv_columns_stay_aligned_for_missing_domain(monkeypatch, capsys):
    import csv as _csv
    code, out = run_cli(monkeypatch, capsys, ["missing-domain.com", "good.com", "--csv"])
    rows = list(_csv.reader(out.out.splitlines()))
    assert all(len(r) == len(rows[0]) for r in rows)
    assert rows[1][3] == "domain not found" and rows[2][4] == "pass"


def test_excel_csv_with_bom_and_email_column(monkeypatch, capsys, tmp_path):
    f = tmp_path / "leads.csv"
    f.write_bytes("﻿First Name,Email,Company\nPriya,priya@good.com,Good\nRaj,raj@good.com,Good\n".encode("utf-8"))
    code, out = run_cli(monkeypatch, capsys, ["-f", str(f), "--json"])
    assert code == 0 and json.loads(out.out)["domain"] == "good.com"


def test_column_flag_by_name_and_number(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("name,site\nA,good.com\n")
    assert cli._read_domains(str(f), "site") == ["good.com"]
    g = tmp_path / "e.csv"
    g.write_text("A,good.com\nB,other.com\n")
    assert cli._read_domains(str(g), "2") == ["good.com", "other.com"]


def test_missing_column_is_clean_error(monkeypatch, capsys, tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("name,site\nA,good.com\n")
    code, out = run_cli(monkeypatch, capsys, ["-f", str(f), "-c", "nope"])
    assert code == 2 and "not found" in out.err


def test_unknown_header_row_skipped(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("Sending Domains List\ngood.com\n")
    assert cli._read_domains(str(f)) == ["good.com"]


def test_ascii_icons_on_non_utf8_console():
    class Cp1252:
        encoding = "cp1252"

    class Utf8:
        encoding = "utf-8"

    assert cli._icons_for(Cp1252()) == cli.ASCII_ICONS
    assert cli._icons_for(Utf8()) == cli.ICONS
