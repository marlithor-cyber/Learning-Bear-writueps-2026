# Web Chall 1

Author: `marlithor-cyber`

Challenge name: `Chess`

## Summary

The challenge exposes a websocket chess server and tells you to beat Stockfish.

Relevant files:

- `play_challenge.py`
- `solve.py`

`play_challenge.py` is the normal client: it waits for `game_start`, sends one move, waits for `move_made`, and only plays again after black responds.

`solve.py` contains an extra `--burst` mode that sends multiple move messages back-to-back without waiting for any server response:

```python
if burst:
    for item in moves:
        payload = {"type": "move", "move": item}
        await ws.send(json.dumps(payload))
```

That is the bug path.

## Vulnerability

The websocket backend accepts several white moves in a row before the black Stockfish side responds.

So instead of playing a real game, you can queue a whole mating line immediately after the connection starts. The server processes the queued white moves on the same board state progression, and black never gets its turn between them.

## Exploit

Use `solve.py` in burst mode and send a simple Scholar's Mate sequence as four consecutive white moves:

```bash
python3 solve.py --burst e2e4 d1h5 f1c4 h5f7
```

Each argument becomes:

```json
{"type":"move","move":"..."}
```

and `solve.py` transmits them without waiting for replies.

The important point is not the specific opening theory, but the race/turn-desync:

1. White sends multiple legal moves in one burst.
2. The server accepts them sequentially.
3. Stockfish as black does not move between those messages.
4. White reaches a forced mate position immediately.

## Notes

- The public LB API still showed the challenge metadata on March 3, 2026, confirming the title `Chess` and the description `Beat Stockfish. You have no time limit.`
- The live chess backend at `51.250.116.20:4832` was timing out during this pass, so I could not re-fetch and re-verify the final flag from the remote service.
- The exploit itself is directly supported by the provided `solve.py`, which was clearly adapted for queued move submission rather than ordinary play.
