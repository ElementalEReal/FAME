from __future__ import annotations
import os
from contextlib import contextmanager

@contextmanager
def database():
    # psycopg is imported lazily so pure unit tests do not require a database.
    import psycopg
    url = os.getenv('FAME_DATABASE_URL')
    if not url:
        raise RuntimeError('FAME_DATABASE_URL_NOT_CONFIGURED')
    with psycopg.connect(url, connect_timeout=5, options='-c statement_timeout=10000') as conn:
        with conn.transaction():
            yield conn
