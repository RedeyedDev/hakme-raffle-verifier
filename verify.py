#!/usr/bin/env python3
"""Independent fairness check for Hak Me raffles. Standard library only.

A draw is fully determined by two inputs nobody controls alone:
  * a secret server seed, whose sha256 (the commitment) is public from the
    moment the raffle is created — so the seed can't be swapped later;
  * a drand quicknet round (https://drand.love) that is published only after
    ticket sales close — so nobody, the operator included, knows the outcome
    while tickets can still be bought.

Algorithm:
  1. sha256(seed) == drawSeedHash
  2. drand round: randomness == sha256(signature); round time >= endAt + 30 s
     (the round is pinned as the first one >= 30 s after sales close)
  3. drawKey = HMAC-SHA256(key=seed, msg=drandRandomness)       (hex strings as UTF-8)
     draws without a drand round (older raffles): drawKey = seed
  4. ticketList = [[userId, tickets], ...] sorted by userId
     ticketListHash = sha256(JSON.stringify(ticketList))        (no spaces)
  5. for prize i = 0, 1, ...  (awarded prizes by position ASC, id ASC):
       h = HMAC-SHA256(drawKey, "{contestId}:{i}:{ticketListHash}")
       target = uint32_be(h[0:4]) / 2^32 * (sum of remaining tickets)
       winner = first entry whose running ticket sum exceeds target
       the winner burns one ticket

This script checks the beacon's randomness against its signature but not the
BLS signature itself (no stdlib BLS). The browser verifier (index.html) does
the full BLS check, as does the drand CLI.

Usage:
    python3 verify.py 12                 # fetch contest #12 from the public API
    python3 verify.py <seed hash>        # or find the raffle by its seed commitment
    python3 verify.py draw.json          # or verify a saved /fairness response
    python3 verify.py 12 --api https://api.redeyedlabs.com
"""

import hashlib
import hmac
import json
import re
import sys
import urllib.request
from datetime import datetime

DEFAULT_API = "https://api.redeyedlabs.com"
DRAND_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_GENESIS = 1692803367
DRAND_PERIOD = 3
DRAND_RELAYS = ["https://api.drand.sh", "https://api2.drand.sh", "https://drand.cloudflare.com"]
CLOSE_MARGIN_SEC = 30


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "hakme-raffle-verifier"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def fetch_drand(round_no):
    last = None
    for relay in DRAND_RELAYS:
        try:
            return get_json(f"{relay}/{DRAND_CHAIN_HASH}/public/{round_no}")
        except Exception as e:  # noqa: BLE001 — try the next relay
            last = e
    raise RuntimeError(f"drand round {round_no} unavailable: {last}")


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    api = DEFAULT_API
    if "--api" in sys.argv:
        api = sys.argv[sys.argv.index("--api") + 1].rstrip("/")
        args = [a for a in args if a != api]
    if len(args) != 1:
        print(__doc__)
        return 2

    src = args[0]
    if src.isdigit():
        data = get_json(f"{api}/contests/{int(src)}/fairness")
    elif re.fullmatch(r"[0-9a-fA-F]{64}", src):
        data = get_json(f"{api}/contests/fairness/by-hash/{src.lower()}")
    else:
        data = json.load(open(src))

    if data.get("status") != "completed" or not data.get("drawSeed"):
        print(f"Contest #{data.get('contestId')} is not drawn yet (status={data.get('status')}).")
        print(f"  commitment sha256(seed) = {data.get('drawSeedHash')}")
        if data.get("drandRound"):
            print(f"  drand round pinned: {data['drandRound']}")
        return 0

    contest_id = int(data["contestId"])
    seed = data["drawSeed"]
    ok = True

    def check(cond, msg):
        nonlocal ok
        ok &= bool(cond)
        print(f"{'✓' if cond else '✗'} {msg}")

    print(f"Contest #{contest_id}: {data.get('title', '')}\n")

    # 1. seed matches the commitment published before the start
    seed_hash = hashlib.sha256(seed.encode()).hexdigest()
    check(seed_hash == (data.get("drawSeedHash") or "").lower(), f"sha256(seed) == commitment  {seed_hash}")

    # 2-3. external randomness
    round_no = data.get("drandRound")
    if round_no:
        beacon = fetch_drand(round_no)
        sig_hash = hashlib.sha256(bytes.fromhex(beacon["signature"])).hexdigest()
        check(int(beacon["round"]) == int(round_no) and sig_hash == beacon["randomness"],
              f"drand round {round_no}: randomness == sha256(signature)  (fetched from drand, not from us)")
        check(beacon["randomness"] == data.get("drandRandomness"),
              "drand randomness matches the one used in the draw")
        round_time = DRAND_GENESIS + (int(round_no) - 1) * DRAND_PERIOD
        close = parse_ts(data["endAt"])
        check(round_time >= close + CLOSE_MARGIN_SEC,
              f"drand round came out {round_time - close:.0f} s after sales closed (must be >= {CLOSE_MARGIN_SEC})")
        if data.get("drawnAt"):
            check(parse_ts(data["drawnAt"]) >= round_time,
                  f"draw ran {parse_ts(data['drawnAt']) - round_time:.0f} s after the round came out")
        draw_key = hmac.new(seed.encode(), beacon["randomness"].encode(), hashlib.sha256).hexdigest()
    else:
        print("· no drand round — older raffle, seed-only commit-reveal (key = seed)")
        draw_key = seed

    # 4. ticket list hash (exactly like JSON.stringify — no spaces)
    entries = sorted(([int(u), int(c)] for u, c in data["participants"] if int(c) > 0), key=lambda e: e[0])
    ticket_hash = hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()
    check(ticket_hash == (data.get("ticketListHash") or "").lower(),
          f"sha256(ticket list) == ticketListHash  ({len(entries)} players, {sum(c for _, c in entries)} tickets)")

    # 5. recompute every winner
    print()
    for w in data["winners"]:
        i = int(w["drawIndex"])
        if not entries:
            check(False, f"prize {i}: ran out of tickets before prizes")
            break
        digest = hmac.new(draw_key.encode(), f"{contest_id}:{i}:{ticket_hash}".encode(), hashlib.sha256).digest()
        target = (int.from_bytes(digest[:4], "big") / 0x100000000) * sum(c for _, c in entries)
        acc, idx = 0, 0
        for j, (_, c) in enumerate(entries):
            acc += c
            if target < acc:
                idx = j
                break
        uid = entries[idx][0]
        check(uid == int(w["userId"]), f"prize {i} «{w.get('displayName') or w['prizeId']}»: recomputed #{uid}, announced #{w['userId']}")
        entries[idx][1] -= 1
        if entries[idx][1] <= 0:
            entries.pop(idx)

    print("\nALL CHECKS PASSED — the draw is reproducible" if ok else "\nMISMATCH — see ✗ above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
