from asucks.base_server import run
from typing import Optional

import asyncio
# pylint: disable=import-error
import click
# pylint: enable=import-error
import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


@click.command()
@click.option('--port', default=1080, help="Server port")
@click.option('--host', default="0.0.0.0", help="Network interface")
@click.option('--username', default=None, help="Username for user/pass auth")
@click.option('--password', default=None, help="Password for user/pass auth")
@click.option('--validator', default=None, help="External validator url")
@click.option('--cafile', default=None, help="Validate certificate")
def main(
    username: Optional[str], password: Optional[str], validator: Optional[str], cafile: Optional[str], host: str, port: int
):
    asyncio.run(run(
        username=username,
        host=host,
        port=port,
        password=password,
        validator=validator,
        cafile=cafile,
    ))


# pylint: disable=no-value-for-parameter
if __name__ == "__main__":
    main()
