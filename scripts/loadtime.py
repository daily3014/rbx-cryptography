import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
HYPERFINE_LINK = Path.home() / "AppData/Local/Microsoft/WinGet/Links/hyperfine.exe"

TARGETS = {
    "library": "",
    "Hashing.SHA2.SHA256": "local _ = C.Hashing.SHA2.SHA256",
    "Hashing.SHA2.SHA512": "local _ = C.Hashing.SHA2.SHA512",
    "Hashing.SHA3": "local _ = C.Hashing.SHA3",
    "Hashing.MD5": "local _ = C.Hashing.MD5",
    "Hashing.SHA1": "local _ = C.Hashing.SHA1",
    "Hashing.Blake2b (64 byte call)": "C.Hashing.Blake2b.Digest(buffer.create(1), 64)",
    "Hashing.Blake3 (64 byte call)": "C.Hashing.Blake3.Digest(buffer.create(1), 64)",
    "Hashing.KMAC": "local _ = C.Hashing.KMAC",
    "Encryption.AEAD": "local _ = C.Encryption.AEAD",
    "Encryption.AES": "local _ = C.Encryption.AES",
    "Verification.EdDSA": "local _ = C.Verification.EdDSA",
    "Verification.MlKEM": "local _ = C.Verification.MlKEM",
    "Verification.MlDSA": "local _ = C.Verification.MlDSA",
    "Utilities.CSPRNG": "local _ = C.Utilities.CSPRNG",
    "Preload() (everything)": "C.Preload()",
}


def find_hyperfine() -> str:
    found = shutil.which("hyperfine")
    if found:
        return found
    if HYPERFINE_LINK.is_file():
        return str(HYPERFINE_LINK)
    raise SystemExit("hyperfine not found: winget install sharkdp.hyperfine")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default=str(SCRIPT_DIR.parent / "src"))
    parser.add_argument("--luau", default="E:/tools/luau.exe")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--filter", help="only targets whose name contains this (the baseline always runs)")
    args = parser.parse_args()

    targets = {name: code for name, code in TARGETS.items() if name == "library" or not args.filter or args.filter in name}

    work = Path(tempfile.mkdtemp(prefix="luau-loadtime-"))
    shutil.copytree(args.src, work / "src")
    commands = []
    for index, (name, code) in enumerate(targets.items()):
        script = f"target{index}.luau"
        (work / script).write_text(f'local C = require("./src")\n{code}\n', encoding="utf-8")
        commands.append(f"{args.luau} --codegen -O2 {script}")

    subprocess.run(
        [find_hyperfine(), "-N", "--warmup", "2", "--runs", str(args.runs), "--style", "none",
         "--export-json", "results.json", *commands],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    results = [result.get("summary", {}).get("time_wall_clock", result) for result in json.loads((work / "results.json").read_text())["results"]]
    baseline = results[0]["mean"]
    print(f"{'mean ms':>8} {'min ms':>8} {'+ over library':>15}  target")
    for name, result in zip(targets, results):
        extra = "" if name == "library" else f"{(result['mean'] - baseline) * 1000:+15.1f}"
        print(f"{result['mean'] * 1000:8.1f} {result['min'] * 1000:8.1f} {extra:>15}  {name}")
    print(f"\nrun folder: {work}")


if __name__ == "__main__":
    main()
