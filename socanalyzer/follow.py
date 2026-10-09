import time


def follow_file(path, parse_line, year, on_new_events, poll_seconds=1.0, stop=lambda: False):
    """Watch a growing log file and report new events as they appear.

    on_new_events(all_events_so_far) is called each time new events arrive.
    stop() lets tests end the loop; in normal use it never returns True.
    """
    events = []
    line_no = 0
    partial = ""

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        while not stop():
            chunk = f.read()
            if not chunk:
                time.sleep(poll_seconds)
                continue

            text = partial + chunk
            lines = text.split("\n")
            partial = lines.pop()       # last piece may be an unfinished line

            added = False
            for line in lines:
                line_no += 1
                if not line.strip():
                    continue
                try:
                    event = parse_line(line, line_no, year)
                except ValueError:
                    continue
                if event:
                    events.append(event)
                    added = True

            if added:
                on_new_events(events)