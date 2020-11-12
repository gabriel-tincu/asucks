from asucks.base_server import ServerConfig, StreamServer
from asucks.socket_api import SocketServer
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
@click.option("--cafile", default=None, help="Remote validator certificate file")
@click.option("--log-level", default="INFO", help="Log level visible")
@click.option("--use-sockets", default=False, help="Use the base socket server implementation")
def main(
    username: Optional[str], password: Optional[str], validator: Optional[str], cafile: Optional[str], host: str, port: int,
    use_sockets: bool, log_level: str
):
    config = ServerConfig(
        username=username,
        host=host,
        port=port,
        password=password,
        validator=validator,
        ca_file=cafile,
    )
    asyncio.run(run_main(config=config, use_sockets=use_sockets, log_level=log_level))


async def run_main(config: ServerConfig, use_sockets: bool, log_level: str):
    logging.basicConfig(level=log_level)
    loop = asyncio.get_running_loop()
    closing = asyncio.Event()
    if use_sockets:
        log.info("Using socket implementation")
        server_class = SocketServer
    else:
        log.info("Using stream implementation")
        server_class = StreamServer
    server = server_class(config=config, loop=loop, closing=closing)
    await server.run_server()


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    main()
