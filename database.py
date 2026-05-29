"""
database.py - Lightweight SQLite-backed audit log for password analyses.

Only metadata is stored — passwords themselves are NEVER persisted.
The module stores a salted SHA-256 hash of the password so identical
passwords across sessions can be correlated without exposing plaintext.

Schema
──────
  analyses
    id          INTEGER PRIMARY KEY AUTOINCREMENT
    pw_hash     TEXT    NOT NULL          -- salted SHA-256 (hex)
    score       INTEGER NOT NULL
    strength    TEXT    NOT NULL
    entropy     REAL    NOT NULL
    checked_at  TEXT    NOT NULL          -- ISO-8601 UTC
    tags        TEXT                      -- optional comma-separated labels
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from analyzer import AnalysisResult


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH  = Path.home() / ".securepassanalyzer" / "history.db"
_HASH_SALT_ENV    = "SECUREPASS_HASH_SALT"
_FALLBACK_SALT    = "secure-pass-analyzer-static-salt-v1"  # override via env
_SCHEMA_VERSION   = 1


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_salt() -> str:
    """Read the HMAC salt from the environment, falling back to a static value."""
    salt = os.environ.get(_HASH_SALT_ENV, _FALLBACK_SALT)
    if salt == _FALLBACK_SALT:
        import warnings
        warnings.warn(
            f"Using the default hash salt.  Set the {_HASH_SALT_ENV!r} "
            "environment variable to a secret value for better privacy.",
            stacklevel=3,
        )
    return salt


def _hash_password(password: str) -> str:
    """Return a salted SHA-256 hex digest of *password*."""
    salt  = _get_salt()
    token = f"{salt}:{password}"
    return hashlib.sha256(token.encode()).hexdigest()


def _utcnow() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Row dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnalysisRecord:
    """One row returned from the *analyses* table."""

    id:         int
    pw_hash:    str
    score:      int
    strength:   str
    entropy:    float
    checked_at: str
    tags:       Optional[str]

    def __str__(self) -> str:
        tag_str = f"  tags={self.tags}" if self.tags else ""
        return (
            f"[{self.id:>4}] {self.checked_at}  "
            f"score={self.score:>3}/100  "
            f"strength={self.strength:<12}"
            f"{tag_str}"
        )


# ---------------------------------------------------------------------------
# Database manager
# ---------------------------------------------------------------------------

class PasswordDatabase:
    """
    Context-manager-aware SQLite database for password analysis audit logs.

    Usage
    ─────
    >>> with PasswordDatabase() as db:
    ...     db.save(result, password)
    ...     recent = db.recent(n=5)

    Parameters
    ----------
    path:
        Path to the SQLite file.  The parent directory is created if absent.
        Pass ``":memory:"`` for an in-memory database (testing / ephemeral).
    """

    def __init__(self, path: Path | str = _DEFAULT_DB_PATH) -> None:
        self._path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None

    # ── Lifecycle ──────────────────────────────────────────────────────

    def connect(self) -> "PasswordDatabase":
        if self._path != Path(":memory:"):
            self._path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self._path),
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._migrate()
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # Context manager support
    def __enter__(self) -> "PasswordDatabase":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.close()

    # ── Internal ───────────────────────────────────────────────────────

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        if not self._conn:
            raise RuntimeError("Database is not connected.  Use connect() first.")
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cursor.close()

    def _migrate(self) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    pw_hash    TEXT    NOT NULL,
                    score      INTEGER NOT NULL,
                    strength   TEXT    NOT NULL,
                    entropy    REAL    NOT NULL,
                    checked_at TEXT    NOT NULL,
                    tags       TEXT
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_checked_at ON analyses(checked_at);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_score ON analyses(score);"
            )

    # ── Public API ─────────────────────────────────────────────────────

    def save(
        self,
        result:   AnalysisResult,
        password: str,
        tags:     Optional[str] = None,
    ) -> int:
        """
        Persist an analysis result.

        Parameters
        ----------
        result:
            The :class:`~analyzer.AnalysisResult` to store.
        password:
            The plaintext password — stored only as a salted hash.
        tags:
            Optional comma-separated labels (e.g. ``"work,generated"``).

        Returns
        -------
        int
            The auto-assigned row ID.
        """
        pw_hash = _hash_password(password)
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO analyses (pw_hash, score, strength, entropy, checked_at, tags)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    pw_hash,
                    result.score,
                    result.strength.value,
                    round(result.entropy_bits, 4),
                    _utcnow(),
                    tags,
                ),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def recent(self, n: int = 10) -> List[AnalysisRecord]:
        """Return the *n* most recent analysis records."""
        if not (1 <= n <= 1000):
            raise ValueError("n must be between 1 and 1 000.")
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM analyses ORDER BY id DESC LIMIT ?;", (n,)
            )
            return [AnalysisRecord(**dict(row)) for row in cur.fetchall()]

    def search_by_strength(self, strength: str) -> List[AnalysisRecord]:
        """Return all records with a given strength label."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM analyses WHERE strength = ? ORDER BY id DESC;",
                (strength,),
            )
            return [AnalysisRecord(**dict(row)) for row in cur.fetchall()]

    def stats(self) -> dict:
        """Return aggregate statistics across all stored analyses."""
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)           AS total,
                    ROUND(AVG(score),1) AS avg_score,
                    MAX(score)         AS max_score,
                    MIN(score)         AS min_score,
                    ROUND(AVG(entropy),1) AS avg_entropy
                FROM analyses;
                """
            )
            row = cur.fetchone()
            return dict(row) if row else {}

    def delete_record(self, record_id: int) -> bool:
        """Delete a single record by *record_id*.  Returns True if deleted."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM analyses WHERE id = ?;", (record_id,))
            return cur.rowcount > 0

    def clear_all(self) -> int:
        """Delete ALL records.  Returns the number of rows removed."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM analyses;")
            return cur.rowcount