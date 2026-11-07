#!/usr/bin/env python3
"""Say how Autobahn's run went, and fail the build if a case did.

`wstest` writes one entry per case into `index.json`, each with the behaviour it
observed: `OK`, `NON-STRICT` (the case passed, but not the way the suite would
prefer), `FAILED`, or `INFORMATIONAL` for a case that asserts nothing. A failure
here is a case that did not do what RFC 6455 or RFC 7692 says it must.

A case also carries how long it took. The suite has no opinion on that, but this
library does: the slowest cases send a thousand 128 KiB messages through one
connection, so their time is what says whether the compressed path is still
linear in the octets it carries. `CEILING` names the cases where a regression
would show up as seconds rather than as a failure, and the time each is allowed.
"""

import json
import sys

# Seconds after which a case fails the run, by case id. Everything else is only
# reported: the suite's own timeout is that bound.
#
# This is a guard against a regression, not a benchmark. The same commit measured
# 8.8 s and 11.5 s for 12.2.10 on two runners of the same size, so a ceiling at the
# ten seconds the project asks for turns a shared machine into a red build with
# nothing wrong in the code. Fifteen is still a quarter of the way to the 78 s this
# case took before the compressor learned to resume inside a symbol, and a run that
# drifts towards it is visible in TARGET below long before it fails.
CEILING = {
    # A thousand 128 KiB messages through one connection, which is the case that
    # says whether a message costs the octets it carries or the square of them.
    "12.2.10": 15.0,
}

# The time the project asks for. Passing it is a note, not a failure.
TARGET = {
    "12.2.10": 10.0,
}


def main(path):
    index = json.load(open(path, encoding="utf-8"))
    counts = {}
    failed = []
    slow = []
    over = []
    for agent, cases in index.items():
        for case, entry in cases.items():
            behavior = entry.get("behavior", "MISSING")
            counts[behavior] = counts.get(behavior, 0) + 1
            if behavior not in ("OK", "INFORMATIONAL", "NON-STRICT"):
                failed.append((agent, case, behavior, entry.get("behaviorClose", "")))
            seconds = entry.get("duration", 0) / 1000.0
            slow.append((seconds, case, behavior))
            allowed = CEILING.get(case)
            if allowed is not None and seconds > allowed:
                over.append((case, seconds, allowed))
    for behavior in sorted(counts):
        print("%-14s %d" % (behavior, counts[behavior]))
    slow.sort(reverse=True)
    if not slow:
        # No report at all means the suite never reached the endpoint: it is the
        # one failure that would otherwise read as a run of zero failures.
        print("no case was reported: the suite did not reach the endpoint")
        return 1
    total = sum(seconds for seconds, _, _ in slow)
    print("%-14s %d cases, %.1f s" % ("", len(slow), total))
    print("slowest:")
    for seconds, case, behavior in slow[:5]:
        print("  %-10s %6.1f s  %s" % (case, seconds, behavior))
    for agent, case, behavior, close in failed:
        print("FAILED %s %s: %s (close %s)" % (agent, case, behavior, close))
    for seconds, case, _ in slow:
        target = TARGET.get(case)
        if target is not None and seconds > target:
            print(
                "over the %g s asked of %s: %.1f s%s"
                % (
                    target,
                    case,
                    seconds,
                    "" if CEILING.get(case, 0) > seconds else ", and over the limit",
                )
            )
    for case, seconds, allowed in over:
        print(
            "SLOW %s: %.1f s, over the %g s this case is allowed"
            % (case, seconds, allowed)
        )
    return 1 if failed or over else 0


if __name__ == "__main__":
    sys.exit(
        main(
            sys.argv[1]
            if len(sys.argv) > 1
            else "_build/autobahn/run-1/clients/index.json"
        )
    )
