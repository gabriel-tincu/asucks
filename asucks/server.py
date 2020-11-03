from asucks.base_server import ProxyConnection, ServerConfig
from asyncio.streams import StreamReader, StreamWriter
from typing import Optional

import asyncio
# pylint: disable=import-error
import click
# pylint: enable=import-error
import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def conn_factory(config: ServerConfig):
    async def proxy(reader: StreamReader, writer: StreamWriter) -> None:
        conn = ProxyConnection(reader=reader, writer=writer, config=config)
        await conn.process_request()
        log.info("Done processing request")

    return proxy


async def run(
    username: Optional[str], password: Optional[str], validator: Optional[str], cafile: Optional[str], host: str, port: int
):
    config = ServerConfig(
        host=host,
        port=int(port),
        username=username,
        password=password,
        validator=validator,
        ca_file=cafile,
    )
    log.debug("Got config: %r", config)
    loop = asyncio.get_running_loop()
    server = await asyncio.start_server(conn_factory(config), host=config.host, port=config.port, loop=loop)
    addr = server.sockets[0].getsockname()
    log.info("Serving on %s", addr)
    async with server:
        await server.serve_forever()


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
