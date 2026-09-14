import argparse
import json
from pathlib import Path

from .store import EventStore


def main():
    parser = argparse.ArgumentParser(description='Import immutable Windows sensor batches; never deletes source evidence.')
    parser.add_argument('spool')
    parser.add_argument('--db', default=str(Path.home() / '.jarvis' / 'native-events.db'))
    args = parser.parse_args()
    store = EventStore(args.db)
    try:
        result = store.import_directory(args.spool)
        print(json.dumps(result, indent=2))
        return 1 if result['errors'] else 0
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(main())
