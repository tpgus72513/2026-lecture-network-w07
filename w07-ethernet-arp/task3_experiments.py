#!/usr/bin/env python3
"""Task 3 · compare eviction/admission policies on bench.py's trace.

    python3 task3_experiments.py > out/task3-experiments.txt
"""
import contextlib, io, zlib
from collections import OrderedDict
import bench

BC = bench.BROADCAST


class Base:
    def __init__(self, ports, capacity):
        self.ports, self.capacity, self.table = ports, capacity, {}

    def forward(self, dst, in_port):
        if dst == BC or dst not in self.table:
            return [p for p in range(self.ports) if p != in_port]
        out = self.table[dst]
        return [] if out == in_port else [out]


class LRU(Base):
    def __init__(self, *a):
        super().__init__(*a); self.table = OrderedDict()

    def handle(self, frame, in_port):
        src, dst, _ = frame
        if src in self.table:
            self.table.move_to_end(src)
        elif len(self.table) >= self.capacity:
            self.table.popitem(last=False)
        self.table[src] = in_port
        if dst in self.table:
            self.table.move_to_end(dst)
        return self.forward(dst, in_port)


def make_lfu(admit, count_dst, halve_every=None):
    class LFU(Base):
        def __init__(self, *a):
            super().__init__(*a); self.freq = {}; self.n = 0

        def bump(self, mac):
            self.freq[mac] = self.freq.get(mac, 0) + 1

        def handle(self, frame, in_port):
            src, dst, _ = frame
            self.n += 1
            if halve_every and self.n % halve_every == 0:
                self.freq = {m: c // 2 for m, c in self.freq.items() if c // 2}
            self.bump(src)
            if count_dst and dst != BC:
                self.bump(dst)
            if src not in self.table and len(self.table) >= self.capacity:
                victim = min(self.table, key=lambda m: self.freq.get(m, 0))
                if admit and self.freq[src] <= self.freq.get(victim, 0):
                    return self.forward(dst, in_port)      # decline
                del self.table[victim]
            self.table[src] = in_port
            return self.forward(dst, in_port)
    return LFU


class Sketch:
    """Count-min sketch: fixed memory, never undercounts, may overcount."""
    def __init__(self, width, depth=4):
        self.w, self.rows = width, [[0] * width for _ in range(depth)]

    def _idx(self, mac):
        return [zlib.crc32(f"{i}|{mac}".encode()) % self.w
                for i in range(len(self.rows))]

    def add(self, mac):
        for r, i in zip(self.rows, self._idx(mac)):
            r[i] += 1

    def get(self, mac):
        return min(r[i] for r, i in zip(self.rows, self._idx(mac)))

    def halve(self):
        for r in self.rows:
            r[:] = [c // 2 for c in r]


def make_sketch_lfu(width, admit, halve_every=None):
    class SketchLFU(Base):
        def __init__(self, *a):
            super().__init__(*a); self.f = Sketch(width); self.n = 0

        def handle(self, frame, in_port):
            src, dst, _ = frame
            self.n += 1
            if halve_every and self.n % halve_every == 0:
                self.f.halve()
            self.f.add(src)
            if dst != BC:
                self.f.add(dst)
            if src not in self.table and len(self.table) >= self.capacity:
                victim = min(self.table, key=self.f.get)
                if admit and self.f.get(src) <= self.f.get(victim):
                    return self.forward(dst, in_port)
                del self.table[victim]
            self.table[src] = in_port
            return self.forward(dst, in_port)
    return SketchLFU


class LRUDoorkeeper(LRU):
    """LRU, but a source is admitted to a full table only on its second sighting."""
    def __init__(self, *a):
        super().__init__(*a); self.seen = OrderedDict()

    def handle(self, frame, in_port):
        src, dst, _ = frame
        if src not in self.table and len(self.table) >= self.capacity:
            if src not in self.seen:
                self.seen[src] = None
                if len(self.seen) > self.capacity:
                    self.seen.popitem(last=False)
                if dst in self.table:
                    self.table.move_to_end(dst)
                return self.forward(dst, in_port)
            del self.seen[src]
        return super().handle(frame, in_port)


def make_bounded(limit, halve_every=None):
    """LFU + admission, counts kept for at most `limit` MACs (table + shadow)."""
    class Bounded(Base):
        def __init__(self, *a):
            super().__init__(*a); self.freq = {}; self.n = 0

        def bump(self, mac):
            if mac not in self.freq and len(self.freq) >= limit:
                gone = min((m for m in self.freq if m not in self.table),
                           key=self.freq.get)
                del self.freq[gone]
            self.freq[mac] = self.freq.get(mac, 0) + 1

        def handle(self, frame, in_port):
            src, dst, _ = frame
            self.n += 1
            if halve_every and self.n % halve_every == 0:
                self.freq = {m: c // 2 for m, c in self.freq.items()}
            self.bump(src)
            if dst != BC:
                self.bump(dst)
            if src not in self.table and len(self.table) >= self.capacity:
                victim = min(self.table, key=lambda m: self.freq.get(m, 0))
                if self.freq.get(src, 0) <= self.freq.get(victim, 0):
                    return self.forward(dst, in_port)
                del self.table[victim]
            self.table[src] = in_port
            return self.forward(dst, in_port)
    return Bounded


def oracle(where, frames, capacity):
    """Not a legal switch: pins the 64 most-addressed stations, using the future."""
    from collections import Counter
    top = {m for m, _ in Counter(d for _, d, _, _ in frames if d != BC)
           .most_common(capacity)}
    class Oracle(Base):
        def handle(self, frame, in_port):
            src, dst, _ = frame
            if src in top:
                self.table[src] = in_port
            return self.forward(dst, in_port)
    return Oracle


def main():
    _, where, frames = bench.build()
    variants = [
        ("baseline", __import__("task3_flooding").NaiveSwitch),
        ("LRU", LRU),
        ("LFU src", make_lfu(False, False)),
        ("LFU src+dst", make_lfu(False, True)),
        ("LFU+admit src", make_lfu(True, False)),
        ("LFU+admit s+d", make_lfu(True, True)),
        ("LFU+admit s+d halve10k", make_lfu(True, True, 10_000)),
        ("LRU+doorkeeper", LRUDoorkeeper),
        ("sketch256 LFU", make_sketch_lfu(256, False)),
        ("sketch256 LFU+admit", make_sketch_lfu(256, True)),
        ("sketch64 LFU+admit", make_sketch_lfu(64, True)),
        ("bounded 128", make_bounded(128)),
        ("bounded 256", make_bounded(256)),
        ("bounded 256 halve10k", make_bounded(256, 10_000)),
        ("oracle top-64 (illegal)", oracle(where, frames, bench.CAPACITY)),
    ]
    base = None
    for name, cls in variants:
        with contextlib.redirect_stdout(io.StringIO()):
            r = bench.run(cls, name, where, frames)
        base = base or r["wasted"]
        print(f"  {name:<24} wasted {r['wasted']:>8,}  missed {r['missed']}  "
              f"cut {1 - r['wasted'] / base:>4.0%}")
    ablation(where, frames)


def ablation(where, frames):
    """Switch off one idea of the submitted YourSwitch at a time."""
    from task3_flooding import YourSwitch

    class NoAdmit(YourSwitch):
        def handle(self, frame, in_port):
            if frame[0] not in self.table and len(self.table) >= self.capacity:
                del self.table[min(self.table, key=lambda m: self.freq.get(m, 0))]
            return super().handle(frame, in_port)

    class NoHalve(YourSwitch):
        HALVE_SECONDS = float("inf")

    declined = 0

    class Counting(YourSwitch):
        def handle(self, frame, in_port):
            nonlocal declined
            out = super().handle(frame, in_port)
            declined += frame[0] not in self.table
            return out

    def wasted(cls):
        with contextlib.redirect_stdout(io.StringIO()):
            return bench.run(cls, "x", where, frames)["wasted"]

    mine = wasted(Counting)
    print("\n  # ablation of the submitted YourSwitch (same trace)")
    print(f"  YourSwitch (LFU src+dst, admission, 128 counters, halve/1000 s)"
          f"  wasted {mine:,}")
    for label, cls in [("admission off", NoAdmit), ("halving off", NoHalve)]:
        w = wasted(cls)
        print(f"  - {label:<62} wasted {w:,}  ({w - mine:+,})")
    print(f"  learning declined {declined:,} times "
          "(newcomer no busier than coldest entry)")
    attack(where, frames)


def attack(where, frames):
    """R6: after every real frame, one broadcast from a never-seen fake source."""
    from task3_flooding import NaiveSwitch, YourSwitch
    noisy = []
    for i, f in enumerate(frames):
        noisy.append(f)
        noisy.append((f"02:66:{i // 65536 % 256:02x}:{i // 256 % 256:02x}:"
                      f"{i % 256:02x}:00", BC, f[2], 0))
    print("\n  # R6 attack: one fake source MAC per real frame, all on port 0")
    for name, cls in [("baseline", NaiveSwitch), ("YourSwitch", YourSwitch)]:
        with contextlib.redirect_stdout(io.StringIO()):
            clean = bench.run(cls, name, where, frames)["wasted"]
            hit = bench.run(cls, name, where, noisy)["wasted"]
        print(f"  {name:<11} wasted clean {clean:>8,}  under attack {hit:>8,}  "
              f"({hit / clean:.2f}x)")


if __name__ == "__main__":
    main()
