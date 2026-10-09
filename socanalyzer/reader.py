def read_events(path, parse_line, year=None):
    """Read a log file line by line using the given parse_line function.

    Returns (list_of_events, number_of_bad_lines).
    - blank lines are skipped silently
    - parse_line raising ValueError marks the line as unreadable
    - parse_line returning None means "valid but not interesting"
    """
    events = []
    bad_lines = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                event = parse_line(line, line_no, year)
            except ValueError:
                bad_lines += 1
                continue
            if event:
                events.append(event)

    return events, bad_lines