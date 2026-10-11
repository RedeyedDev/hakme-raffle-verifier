# Hak Me Raffle Verifier

Recompute any [Hak Me](https://t.me/hakme_app_bot/hakme) raffle draw yourself and check that the announced winners are exactly the ones the rules produce.

**Open in the browser:** https://redeyeddev.github.io/hakme-raffle-verifier/?contest=12, or by the seed hash shown in the raffle: `?hash=<64 hex chars>`. The page is in English by default; `?lang=ru` or `?lang=ua` switches the language.

**Or run locally** (Python 3, standard library only):

```bash
python3 verify.py 12            # fetches https://api.redeyedlabs.com/contests/12/fairness
python3 verify.py <seed hash>   # finds the raffle by its seed commitment
python3 verify.py saved.json    # verifies a saved response offline
```

## Why you can trust the draw

The winners depend on two inputs, and neither side controls both:

| Input | Fixed when | Who controls it |
|---|---|---|
| Secret server `seed` | Before sales open. `sha256(seed)` is shown in the raffle from the start | The game, but it can't change the seed later without the hash giving it away |
| [drand](https://drand.love) quicknet round | Pinned when sales close as the first round ≥ 30 s after closing. It doesn't exist until then | The League of Entropy, a threshold network of independent organisations. Nobody can predict it or forge it |

Without the beacon, the game would know its own seed in advance and could compute the outcome before the draw. With the beacon, nobody knows the outcome while tickets can still be bought, the game included.

## Algorithm

```
1. sha256(seed) == drawSeedHash
2. drand round R: valid BLS signature (quicknet public key); randomness = sha256(signature)
   time(R) >= endAt + 30 s; the draw ran after time(R)
3. drawKey = HMAC-SHA256(key = seed, msg = drandRandomness)      // hex strings as UTF-8
4. ticketList = [[userId, tickets], …] sorted by userId
   ticketListHash = sha256(JSON.stringify(ticketList))            // no spaces
5. for prize i = 0, 1, … (awarded prizes by position ASC, id ASC):
     h      = HMAC-SHA256(drawKey, `${contestId}:${i}:${ticketListHash}`)
     target = uint32_be(h[0..4]) / 2^32 * (sum of remaining tickets)
     winner = first entry whose running ticket sum exceeds target
     winner burns one ticket (drops out at zero)
```

Raffles drawn before the beacon shipped have `drandRound = null`. They use `drawKey = seed` (commit-reveal only). Raffles drawn before 2026-07-26 used database row order in step 5 and can't be recomputed from the public list.

## Data

`GET https://api.redeyedlabs.com/contests/:id/fairness` needs no auth, and neither does `GET /contests/fairness/by-hash/:seedHash`. The seed, the ticket list and the winners appear once the raffle is completed. Participants are identified only by numeric user id. The game shows you your own id in the raffle's "Fairness" block, so you can find your tickets in the list.

drand beacons are fetched directly from the drand relays (`api.drand.sh`, `api2.drand.sh`, `drand.cloudflare.com`), not through the game.

## Files

- `index.html`: the browser verifier. Plain ES module, no build step, uses WebCrypto for SHA-256/HMAC.
- `vendor/noble-bls12-381.js`: [`@noble/curves`](https://github.com/paulmillr/noble-curves) 1.9.1 (with `@noble/hashes` 1.8.0), bundled with esbuild so the page doesn't depend on a CDN. It's used only for the BLS check. To rebuild it and compare:
  ```bash
  npm i @noble/curves@1.9.1 esbuild
  echo "export { bls12_381 } from '@noble/curves/bls12-381';" > e.mjs
  npx esbuild e.mjs --bundle --format=esm --minify --legal-comments=inline --outfile=noble-bls12-381.js
  ```
  sha256 `620155c9b147f1a06763272b90c0bfa2b922d938b84ddba6262386d3a7ee05bf`. The exact bytes can vary with the esbuild version.
- `verify.py`: the same checks in Python. It checks `randomness == sha256(signature)` but not the BLS signature itself, since there's no BLS in the standard library. For that, use the browser page or the drand CLI.

If you open `index.html` from disk (`file://`), Chrome blocks module imports, so the BLS check is skipped and says so. Every other check still runs.

License: MIT.
