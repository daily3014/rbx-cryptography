import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

SLOT_WARNING = 20

def run_workload(luau: Path, workload: str, flag: str) -> None:
    result = subprocess.run([str(luau), "--codegen", "-O2", flag, workload], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.startswith("FAILED"):
            print(f"[{flag}] {line}")
    if result.returncode != 0:
        raise SystemExit(f"workload failed under {flag} ({result.returncode}):\n{result.stderr}")


def read_counters(path: Path) -> tuple[dict, dict]:
    """(file, defline) -> {line: [regular, fallback, vmexit]}, and (file, defline) -> name"""
    counters = defaultdict(dict)
    names = {}
    key = None
    file = None
    for raw in path.read_text().splitlines():
        if raw.startswith("fl="):
            file = raw[3:]
        elif raw.startswith("fn="):
            name, _, line = raw[3:].rpartition(":")
            if not name:
                name, line = raw[3:], "1"
            key = (file, int(line))
            names.setdefault(key, name)
        elif raw and raw[0].isdigit() and key:
            line, regular, fallback, vmexit = (int(part) for part in raw.split())
            counts = counters[key].setdefault(line, [0, 0, 0])
            counts[0] += regular
            counts[1] += fallback
            counts[2] += vmexit
    return counters, names


def read_profile(path: Path) -> tuple[dict, dict, int]:
    """Self time per (file, defline), charged to the innermost Luau frame (stacks list it first)."""
    self_time = defaultdict(int)
    names = {}
    total = 0
    for raw in path.read_text().splitlines():
        weight, _, stack = raw.partition(" ")
        weight = int(weight)
        total += weight
        for frame in stack.split(";"):
            file, name, line = frame.split(",")
            if file in ("GC", "[C]") or not line:
                continue
            key = (file, int(line))
            self_time[key] += weight
            names.setdefault(key, name)
            break
    return self_time, names, total


def write_folded(profile: Path, folded: Path) -> None:
    """luau.exe lists the count first and the innermost frame first; flamegraph tools want the reverse."""
    lines = []
    for raw in profile.read_text().splitlines():
        weight, _, stack = raw.partition(" ")
        frames = []
        for frame in reversed(stack.split(";")):
            file, name, line = frame.split(",")
            frames.append(f"{name or '<anonymous>'} ({file}:{line})" if line else name or file)
        lines.append(f"{';'.join(frames)} {weight}")
    folded.write_text("\n".join(lines) + "\n")


def compile_stats(luau_compile: Path, files: list[str], stats_file: Path) -> dict:
    subprocess.run(
        [str(luau_compile), "--codegennull", "-O2", "--record-stats=function", f"--stats-file={stats_file}", *files],
        capture_output=True,
        check=True,
    )
    return json.loads(stats_file.read_text())


def source_line(cache: dict, file: str, line: int) -> str:
    if file not in cache:
        try:
            cache[file] = Path(file).read_text(encoding="utf-8").splitlines()
        except OSError:
            cache[file] = []
    lines = cache[file]
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def print_compile(stats: dict, top: int) -> None:
    print("\n== compile (luau-compile --codegennull -O2)")
    rows = sorted(((entry["codegenTime"], file, entry["lowerStats"]) for file, entry in stats.items()), reverse=True)
    print(f"{'codegen ms':>10} {'max slots':>9} {'spills':>7}  file")
    for codegen_time, file, lower in rows[:top]:
        spills = lower["spillsToSlot"] + lower["spillsToRestore"]
        slots = lower["maxSpillSlotsUsed"]
        mark = "  <- near the spill slot limit" if slots >= SLOT_WARNING else ""
        print(f"{codegen_time * 1000:10.1f} {slots:9} {spills:7}  {file}{mark}")
    print(f"{sum(row[0] for row in rows) * 1000:10.1f} ms total across {len(rows)} files")

    failed = False
    for _, file, lower in rows:
        if lower["regAllocErrors"] or lower["loweringErrors"] or lower["skippedFunctions"]:
            failed = True
            missing = [f"{function['name']}:{function['line']}" for function in lower["functions"] if function["asmCount"] == 0]
            print(
                f"  FAILED {file}: regalloc errors {lower['regAllocErrors']}, lowering errors "
                f"{lower['loweringErrors']}, skipped {lower['skippedFunctions']}; no native code: "
                f"{', '.join(missing) or '(none listed)'}"
            )
    if not failed:
        print("  every function compiled: no regalloc or lowering errors, none skipped")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default=str(SCRIPT_DIR.parent / "src"), help="library tree to copy and run")
    parser.add_argument("--workload", default=str(SCRIPT_DIR / "counters_workload.luau"))
    parser.add_argument("--luau", default="E:/tools/luau.exe")
    parser.add_argument("--perfgraph", default="E:/tools/luau-src/tools/perfgraph.py")
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--min-share", type=float, default=0.005, help="profile share that counts as hot")
    parser.add_argument("--min-count", type=int, default=2, help="fewest fallbacks plus exits worth listing")
    args = parser.parse_args()

    luau = Path(args.luau).resolve()
    luau_compile = luau.with_name("luau-compile.exe")

    work = Path(tempfile.mkdtemp(prefix="luau-counters-"))
    shutil.copytree(args.src, work / "src")
    shutil.copy(args.workload, work / "workload.luau")
    os.chdir(work)

    run_workload(luau, "workload.luau", "--profile")
    run_workload(luau, "workload.luau", "--counters")
    counters, counter_names = read_counters(Path("callgrind.out"))
    self_time, profile_names, total_time = read_profile(Path("profile.out"))
    write_folded(Path("profile.out"), Path("profile.folded"))
    if Path(args.perfgraph).is_file():
        with open("profile.svg", "w", encoding="utf-8") as svg:
            subprocess.run([sys.executable, args.perfgraph, "profile.out"], stdout=svg, check=True)
    files = sorted("./" + path.as_posix() for path in Path("src").rglob("*.luau"))
    stats = compile_stats(luau_compile, files, Path("compile_stats.json"))
    sources: dict = {}

    print_compile(stats, args.top)

    print(f"\n== require (module top level, profile run of {total_time / 1e6:.3f} s)")
    top_levels = sorted(
        ((weight, file) for (file, line), weight in self_time.items() if line == 1 and file.startswith("./src/")),
        reverse=True,
    )
    print(f"{'ms':>7} {'share':>6}  file")
    for weight, file in top_levels[: args.top]:
        print(f"{weight / 1000:7.1f} {weight / total_time:6.1%}  {file}")
    print(f"{sum(weight for weight, _ in top_levels) / 1000:7.1f} {sum(weight for weight, _ in top_levels) / total_time:6.1%}  all top levels")

    print("\n== hottest functions (self time, top levels excluded)")
    hottest = sorted(
        ((weight, key) for key, weight in self_time.items() if key[1] != 1 and key[0].startswith("./src/")),
        reverse=True,
    )
    print(f"{'ms':>7} {'share':>6} {'native':>6}  function")
    for weight, (file, line) in hottest[: args.top]:
        native = "yes" if (file, line) in counters else "NO"
        print(f"{weight / 1000:7.1f} {weight / total_time:6.1%} {native:>6}  {file}:{line} {profile_names[(file, line)] or '<anonymous>'}")

    print(f"\n== interpreted (profile share >= {args.min_share:.1%}, not a top level, no native counters)")
    hot_interpreted = sorted(
        (
            (weight, key)
            for key, weight in self_time.items()
            if key[1] != 1 and key not in counters and key[0].startswith("./src/") and weight / total_time >= args.min_share
        ),
        reverse=True,
    )
    for weight, (file, line) in hot_interpreted:
        print(f"{weight / total_time:7.1%}  {file}:{line} {profile_names[(file, line)] or '<anonymous>'}")
    if not hot_interpreted:
        print("  none")

    print(f"\n== slow paths (Fallback + VmExit >= {args.min_count} on a line)")
    rows = []
    hidden = 0
    for key, lines in counters.items():
        if not key[0].startswith("./src/"):
            continue
        for line, (regular, fallback, vmexit) in lines.items():
            if fallback + vmexit >= args.min_count:
                rows.append((fallback + vmexit, key, line, regular, fallback, vmexit))
            elif fallback or vmexit:
                hidden += 1
    rows.sort(reverse=True)
    print(f"{'share':>6} {'regular':>10} {'fallback':>9} {'vmexit':>7}  location / source")
    for _, key, line, regular, fallback, vmexit in rows[: args.top]:
        share = self_time.get(key, 0) / total_time
        print(f"{share:6.1%} {regular:10} {fallback:9} {vmexit:7}  {key[0]}:{line} {counter_names[key]}")
        print(f"{'':37}{source_line(sources, key[0], line)[:100]}")
    if not rows:
        print("  none")
    print(f"  {hidden} lines hidden with fewer than {args.min_count} (one-off cache misses on first run)")
    print(f"\nrun folder: {work}")


if __name__ == "__main__":
    main()
