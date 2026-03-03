# Web Chall 1

Author: `marlithor-cyber`

Challenge name: `Chess`

## Summary

The challenge exposes a websocket chess server and asks you to beat Stockfish.

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

So instead of playing a real game, you can queue a whole mating line immediately after the connection starts. The server processes the queued white moves one after another, and black never gets a turn between them.

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

The important part is not the opening itself, but the turn desync:

1. White sends multiple legal moves in one burst.
2. The server accepts them sequentially.
3. Stockfish as black does not move between those messages.
4. White reaches a forced mate position immediately.

## Notes

- The title on the LB site was `Chess`, with the description `Beat Stockfish. You have no time limit.`
- The exploit is directly reflected in the provided `solve.py`: the whole point of `--burst` is to send queued move messages before the server lets black respond.
- Since the instance is closed now, this writeup focuses on the bug and the winning move sequence rather than replaying the remote interaction.
