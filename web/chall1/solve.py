import asyncio
import json
import subprocess
import sys
from pathlib import Path

import websockets


DEFAULT_URL = "ws://51.250.116.20:4832/ws"
ENGINE_PATH = Path("stockfish/stockfish-ubuntu-x86-64-avx2")


def parse_args(argv: list[str]) -> tuple[str, bool, list[str]]:
    url = DEFAULT_URL
    burst = False
    args = list(argv)
    if args and args[0] == "autoplay":
        args.pop(0)
        if args and args[0].startswith("ws"):
            url = args.pop(0)
        return url, False, ["__AUTOPLAY__"] + args
    if args and args[0].startswith("ws"):
        url = args.pop(0)
    if args and args[0] == "--burst":
        burst = True
        args.pop(0)
    return url, burst, args


async def drain(ws: websockets.WebSocketClientProtocol, timeout: float = 1.0) -> None:
    try:
        while True:
            msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
            print(msg)
    except asyncio.TimeoutError:
        pass


class Engine:
    def __init__(self, path: Path) -> None:
        self.proc = subprocess.Popen(
            [str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.stdin = self.proc.stdin
        self.stdout = self.proc.stdout

    def cmd(self, line: str) -> None:
        self.stdin.write(line + "\n")
        self.stdin.flush()

    def wait_for(self, token: str) -> None:
        while True:
            line = self.stdout.readline()
            if not line:
                raise RuntimeError(f"engine closed while waiting for {token!r}")
            if token in line:
                return

    def init(self) -> None:
        self.cmd("uci")
        self.wait_for("uciok")
        self.cmd("setoption name Threads value 4")
        self.cmd("setoption name Hash value 256")
        self.cmd("isready")
        self.wait_for("readyok")

    def bestmove(self, moves: list[str], movetime_ms: int) -> str:
        cmd = "position startpos"
        if moves:
            cmd += " moves " + " ".join(moves)
        self.cmd(cmd)
        self.cmd(f"go movetime {movetime_ms}")
        while True:
            line = self.stdout.readline()
            if not line:
                raise RuntimeError("engine closed during search")
            line = line.strip()
            if line.startswith("bestmove "):
                return line.split()[1]

    def close(self) -> None:
        try:
            self.cmd("quit")
        except Exception:
            pass
        self.proc.kill()


async def autoplay(url: str, movetime_ms: int) -> None:
    engine = Engine(ENGINE_PATH)
    engine.init()
    moves: list[str] = []
    try:
        async with websockets.connect(url, ping_interval=None) as ws:
            while True:
                raw = await ws.recv()
                print(raw, flush=True)
                msg = json.loads(raw)
                if msg["type"] == "game_start":
                    if msg.get("turn") == "white":
                        move = engine.bestmove(moves, movetime_ms)
                        print(f"ENGINE {move}", flush=True)
                        await ws.send(json.dumps({"type": "move", "move": move}))
                elif msg["type"] == "move_made":
                    moves.append(msg["move"])
                    if msg.get("by") == "black":
                        move = engine.bestmove(moves, movetime_ms)
                        print(f"ENGINE {move}", flush=True)
                        await ws.send(json.dumps({"type": "move", "move": move}))
                elif msg["type"] == "game_over":
                    return
                elif msg["type"] == "error":
                    raise RuntimeError(msg.get("message", "unknown error"))
    finally:
        engine.close()


async def main() -> None:
    url, burst, moves = parse_args(sys.argv[1:])
    if moves and moves[0] == "__AUTOPLAY__":
        movetime_ms = int(moves[1]) if len(moves) > 1 else 3000
        await autoplay(url, movetime_ms)
        return
    async with websockets.connect(url) as ws:
        print(await ws.recv())
        if burst:
            for item in moves:
                payload = json.loads(item[5:]) if item.startswith("json:") else {"type": "move", "move": item}
                await ws.send(json.dumps(payload))
                print(f">>> {payload}")
            await drain(ws, timeout=2.0)
            return

        for item in moves:
            payload = json.loads(item[5:]) if item.startswith("json:") else {"type": "move", "move": item}
            await ws.send(json.dumps(payload))
            print(f">>> {payload}")
            await drain(ws)


if __name__ == "__main__":
    asyncio.run(main())
