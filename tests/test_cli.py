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
