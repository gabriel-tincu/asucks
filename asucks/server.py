from asucks.base_server import ServerConfig
from asucks.socket_api import SocketServer
from asucks.streams_api import StreamServer

import argparse
import asyncio
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 server", prog="asucks.server")
    parser.add_argument("--port", default=1080, type=int, help="Server port")
    parser.add_argument("--host", default="0.0.0.0", help="Network interface")
    parser.add_argument("--username", default=None, help="Username for user/pass auth")
    parser.add_argument("--password", default=None, help="Password for user/pass auth")
    parser.add_argument("--log-level", default="INFO", help="Log level visible")
    parser.add_argument(
        "--use-sockets", default=False, action="store_true", help="Use the base socket server implementation"
    )
    args = parser.parse_args(None)
    logging.basicConfig(level=args.log_level)

    config = ServerConfig(
        username=args.username,
        host=args.host,
        port=args.port,
        password=args.password,
    )
    asyncio.run(run_main(config=config, use_sockets=args.use_sockets))


async def run_main(config: ServerConfig, use_sockets: bool):
    loop = asyncio.get_running_loop()
    closing = asyncio.Event()
    if use_sockets:
        log.info("Using socket implementation")
        server_class = SocketServer
    else:
        log.info("Using stream implementation")
        server_class = StreamServer
    server = server_class(config=config, loop=loop, closing=closing)
    try:
        await server.run_server()
    except asyncio.CancelledError:
        server.close()
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    main()
