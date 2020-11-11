from asucks.base_server import run as stream_run
from asucks.socket_api import run as socket_run
from typing import Optional

import asyncio
# pylint: disable=import-error
import click
# pylint: enable=import-error
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


@click.command()
@click.option("--port", default=1080, help="Server port")
@click.option("--host", default="0.0.0.0", help="Network interface")
@click.option("--username", default=None, help="Username for user/pass auth")
@click.option("--password", default=None, help="Password for user/pass auth")
@click.option("--validator", default=None, help="External validator url")
@click.option("--cafile", default=None, help="Validate certificate")
@click.option("--log-level", default="INFO", help="Log level visible")
@click.option("--use-sockets", default=True, help="Use the base socket server implementation")
def main(
    username: Optional[str], password: Optional[str], validator: Optional[str], cafile: Optional[str], host: str, port: int,
    use_sockets: bool, log_level: str
):
    run_main(username, password, validator, cafile, host, port, use_sockets, log_level)


def run_main(
    username: Optional[str], password: Optional[str], validator: Optional[str], cafile: Optional[str], host: str, port: int,
    use_sockets: bool, log_level: str
):
    logging.basicConfig(level=log_level)
    run = socket_run if use_sockets else stream_run
    asyncio.run(run(
        username=username,
        host=host,
        port=port,
        password=password,
        validator=validator,
        cafile=cafile,
    ))


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    main()
