#!/usr/bin/env python3
"""ONE COMMAND to run the whole Threat Detection Engine.

    python run.py                          # full pipeline on the built-in sample data
    python run.py --logs my_logs.jsonl     # full pipeline on your own logs
    python run.py --logs live.jsonl --follow   # ... then keep watching for new lines

What it does, in order (stops with a clear message if a step fails):
  1. checks your Python version
  2. installs the requirements if they are missing (falls back to a private .venv)
  3. validates every YAML rule and the config
  4. runs the automated tests
  5. runs the detection engine (batch, or live with --follow)

Options:  --logs PATH   --follow   --no-color   --skip-tests
"""
import argparse, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(BASE, ".venv")
TOTAL = 5

if os.name == "nt":
    os.system("")          # lets old Windows consoles show ANSI colours


def step(n, text):
    print(f"\n{'=' * 70}\n [{n}/{TOTAL}] {text}\n{'=' * 70}", flush=True)


def fail(msg, code=1):
    print(f"\nSTOPPED: {msg}", file=sys.stderr)
    sys.exit(code)


def sh(cmd, quiet=False):
    """Run a command inside the project folder; return its exit code."""
    return subprocess.run(cmd, cwd=BASE,
                          stdout=subprocess.DEVNULL if quiet else None,
                          stderr=subprocess.DEVNULL if quiet else None).returncode


def has_yaml(py):
    return sh([py, "-c", "import yaml"], quiet=True) == 0


def venv_python():
    sub = ("Scripts", "python.exe") if os.name == "nt" else ("bin", "python")
    return os.path.join(VENV, *sub)


def ensure_requirements():
    """Return the python executable that has PyYAML available."""
    req = os.path.join(BASE, "requirements.txt")
    if has_yaml(sys.executable):
        print("Requirements already installed (PyYAML found).")
        return sys.executable
    print("PyYAML not found - installing requirements...")
    if sh([sys.executable, "-m", "pip", "install", "-r", req]) == 0 and has_yaml(sys.executable):
        print("Requirements installed.")
        return sys.executable
    print("\nNormal install did not work (common on Linux/macOS system Python).")
    print("Creating a private virtual environment in .venv ...")
    vpy = venv_python()
    if not os.path.exists(vpy) and sh([sys.executable, "-m", "venv", VENV]) != 0:
        fail("could not create a virtual environment. Install PyYAML manually: pip install -r requirements.txt")
    if sh([vpy, "-m", "pip", "install", "-r", req]) != 0 or not has_yaml(vpy):
        fail("could not install requirements (is the internet connection working?). "
             "Try manually: pip install -r requirements.txt")
    print("Requirements installed in .venv (used automatically from now on).")
    return vpy


def main():
    ap = argparse.ArgumentParser(description="Run the complete threat detection pipeline with one command")
    ap.add_argument("--logs", help="normalized JSONL log file (default: built-in sample data)")
    ap.add_argument("--follow", action="store_true", help="live mode: keep watching the log file")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    ap.add_argument("--skip-tests", action="store_true", help="skip step 4 (faster start)")
    args = ap.parse_args()

    t0 = time.time()
    if args.logs and not args.follow and not os.path.exists(args.logs):
        fail(f"log file not found: {args.logs}")

    step(1, "Checking Python version")
    if sys.version_info < (3, 8):
        fail(f"Python 3.8+ is required, you have {sys.version.split()[0]}")
    print(f"Python {sys.version.split()[0]} - OK")

    step(2, "Checking / installing requirements")
    py = ensure_requirements()

    step(3, "Validating YAML rules and config")
    if sh([py, "main.py", "--validate-rules"]) != 0:
        fail("rule or config validation failed - fix the message above and run again")

    step(4, "Running automated tests")
    if args.skip_tests:
        print("Skipped (--skip-tests).")
    elif sh([py, "-m", "unittest", "discover", "-s", "tests"]) != 0:
        fail("automated tests failed - the engine is not safe to run until they pass "
             "(use --skip-tests to override)")
    else:
        print("All tests passed.")

    step(5, "Running the detection engine" + (" (LIVE mode)" if args.follow else ""))
    cmd = [py, "main.py"]
    if args.logs:
        cmd += ["--logs", args.logs]
    if args.follow:
        cmd.append("--follow")
    if args.no_color:
        cmd.append("--no-color")
    try:
        code = sh(cmd)
    except KeyboardInterrupt:
        code = 0
    if code != 0:
        fail("the engine stopped with an error (see message above)", code)

    print(f"\nDONE in {time.time() - t0:.1f}s. Alerts saved to: "
          f"{os.path.join(BASE, 'output', 'alerts.jsonl')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
