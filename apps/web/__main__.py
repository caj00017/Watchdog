from __future__ import annotations

import uvicorn

from apps.web.main import create_app
from apps.web.security import validate_loopback_configuration
from watchdog.config import Settings


def main() -> int:
    settings = Settings()
    if not settings.local_interfaces_enabled:
        raise SystemExit("local interfaces are disabled")
    validate_loopback_configuration(settings)
    uvicorn.run(
        create_app(settings),
        host=settings.local_interfaces_host,
        port=settings.local_interfaces_port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        date_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
