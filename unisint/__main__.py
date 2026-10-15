"""Entry point: `python -m unisint` launches the local console."""
from __future__ import annotations

import argparse
import webbrowser

import uvicorn


def main() -> None:
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "search-test":
        from . import searchtest
        raise SystemExit(searchtest.main(sys.argv[2:]))
    ap = argparse.ArgumentParser(description="UNISINT OSINT console")
    ap.add_argument("command", nargs="?", default="serve",
                    choices=["serve", "doctor", "search-test"],
                    help="'serve' (default) launches the UI; 'doctor' runs a "
                         "self-check; 'search-test VALUE --type T' runs one live "
                         "search through the full pipeline")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    if args.command == "doctor":
        from . import doctor
        raise SystemExit(doctor.run())

    url = f"http://{args.host}:{args.port}"
    print(f"\n  UNISINT online -> {url}\n")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    uvicorn.run("unisint.app:app", host=args.host, port=args.port,
                log_level="warning")


if __name__ == "__main__":
    main()
