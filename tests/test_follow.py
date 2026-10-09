from socanalyzer.follow import follow_file


def parse(line, line_no, year):
    return line.strip()


def test_follow_reads_new_lines_and_handles_partial_line(tmp_path):
    log = tmp_path / "live.log"
    log.write_text("one\ntw")                  # second line is unfinished
    seen = []
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        if calls["n"] == 2:
            with open(log, "a") as f:
                f.write("o\nthree\n")          # finishes "two", adds "three"
        return calls["n"] > 3

    follow_file(log, parse, 2026, lambda ev: seen.append(list(ev)),
                poll_seconds=0, stop=stop)

    assert seen[-1] == ["one", "two", "three"]