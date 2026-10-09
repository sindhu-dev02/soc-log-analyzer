from socanalyzer.reader import read_events


def fake_parse(line, line_no, year):
    if line.startswith("bad"):
        raise ValueError("bad line")
    if line.startswith("skip"):
        return None
    return line.strip()


def test_read_events_counts_and_skips(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("good1\n\nbad\nskip me\ngood2\n")

    events, bad = read_events(log, fake_parse)

    assert events == ["good1", "good2"]
    assert bad == 1