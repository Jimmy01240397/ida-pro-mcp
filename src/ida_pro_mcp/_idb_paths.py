"""Pure-Python helpers for IDA database file layout.

No ``idapro`` / ``ida_*`` imports, so this module is unit-testable on
machines without IDA installed (the supervisor tests run there).
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# IDA writes a packed database to ``<binary>.i64`` (64-bit) or
# ``<binary>.idb`` (32-bit) on close, and uses these intermediates
# while a session is open. A clean close packs them back into ``.i64``;
# a crashed worker leaves them behind. The next open then hits
# "Database initialization failed with error 4" and never recovers
# until someone deletes them by hand.
PACKED_SUFFIXES = (".i64", ".idb")
INTERMEDIATE_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def cleanup_stale_idb_intermediates(input_path: str) -> list[Path]:
    """Remove orphaned IDA intermediate files next to *input_path*.

    Conservative: deletes intermediates ONLY when there is NO matching
    ``.i64`` / ``.idb`` packed database alongside. When a packed DB
    exists the intermediates may belong to a legitimately-active
    session and we leave them alone — let idalib decide.

    Returns the paths that were actually removed.
    """
    path = Path(input_path)
    base = str(path)
    packed_exists = any(Path(base + suf).exists() for suf in PACKED_SUFFIXES)
    if packed_exists:
        return []

    removed: list[Path] = []
    for suf in INTERMEDIATE_SUFFIXES:
        candidate = Path(base + suf)
        if not candidate.exists():
            continue
        try:
            candidate.unlink()
            removed.append(candidate)
            logger.warning(
                "Removed stale IDA intermediate %s (no packed .i64/.idb companion)",
                candidate,
            )
        except OSError as e:
            logger.warning(
                "Failed to remove stale IDA intermediate %s: %s", candidate, e
            )
    return removed
