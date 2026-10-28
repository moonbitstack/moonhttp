#!/usr/bin/env python3
"""Say how Autobahn's run went, and fail the build if a case did.

`wstest` writes one entry per case into `index.json`, each with the behaviour it
observed: `OK`, `NON-STRICT` (the case passed, but not the way the suite would
prefer), `FAILED`, or `INFORMATIONAL` for a case that asserts nothing. A failure
here is a case that did not do what RFC 6455 or RFC 7692 says it must.
"""

import json
import sys


def main(path):
    index = json.load(open(path, encoding="utf-8"))
    counts = {}
    failed = []
    for agent, cases in index.items():
        for case, entry in cases.items():
            behavior = entry.get("behavior", "MISSING")
            counts[behavior] = counts.get(behavior, 0) + 1
            if behavior not in ("OK", "INFORMATIONAL", "NON-STRICT"):
                failed.append((agent, case, behavior, entry.get("behaviorClose", "")))
    for behavior in sorted(counts):
        print("%-14s %d" % (behavior, counts[behavior]))
    for agent, case, behavior, close in failed:
        print("FAILED %s %s: %s (close %s)" % (agent, case, behavior, close))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "_build/autobahn/clients/index.json"))
