"""FAME LIVE PostgreSQL connection authority."""

import os
from contextlib import contextmanager
from urllib.parse import urlsplit

import psycopg


@contextmanager
def live_database(read_only=True):
    url = os.getenv("FAME_LIVE_DATABASE_URL")

    if not url:
        raise RuntimeError(
            "FAME_LIVE_DATABASE_URL_NOT_CONFIGURED"
        )

    parsed = urlsplit(url)

    if (
        parsed.scheme not in ("postgresql", "postgres")
        or not parsed.hostname
        or not parsed.hostname.endswith(".neon.tech")
    ):
        raise RuntimeError(
            "FAME_LIVE_DATABASE_URL_INVALID"
        )

    with psycopg.connect(
        url,
        connect_timeout=10,
        sslmode="require",
    ) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL statement_timeout = 10000")
            if read_only:
                conn.execute(
                    "SET TRANSACTION READ ONLY"
                )

            yield conn
