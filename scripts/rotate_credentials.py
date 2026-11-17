"""Rotate stored integration credentials to the configured active key."""

from scripts.common import audit
from web.services.credential_vault import rotate_credentials
from web.services.database import connect_database


def main() -> int:
    conn = connect_database()
    try:
        count = rotate_credentials(conn)
    finally:
        conn.close()
    audit("credential_key_rotation_completed", rotated=count)
    print(f"Rotated {count} credential records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
