from __future__ import annotations

import argparse

from notes_store import clear_exfil_log, clear_notes, format_notes, load_notes, reset_notes


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed or inspect the notes store.")
    parser.add_argument("--reset", action="store_true", help="Replace notes_store.json with the seeded notes")
    parser.add_argument("--empty", action="store_true", help="Empty notes_store.json")
    parser.add_argument("--show", action="store_true", help="Print the current note store")
    parser.add_argument("--clear-exfil", action="store_true", help="Reset data/exfil_log.json to an empty list")
    args = parser.parse_args()

    if args.empty:
        clear_notes()
        print("Cleared notes store.")

    if args.reset:
        notes = reset_notes()
        print(f"Seeded notes store with {len(notes)} notes.")

    if args.clear_exfil:
        clear_exfil_log()
        print("Cleared exfil log.")

    if args.show or not any((args.reset, args.empty, args.clear_exfil)):
        notes = load_notes()
        print(format_notes(notes))


if __name__ == "__main__":
    main()