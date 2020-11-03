from asyncio import AbstractEventLoop
from typing import Any

import socket


def server_bind_socket(host: str, port: int, timeout: int = 5) -> socket:
    # pylint: disable=no-member
    sock = socket.create_server(address=(host, port), family=socket.AF_INET, backlog=10, reuse_port=True)
    # pylint: enable=no-member
    sock.settimeout(timeout)
    sock.setblocking(False)
    return sock


async def run_server(server: socket.socket, loop: AbstractEventLoop, handler: Any) -> None:
    # I would have used callable, but having an async signature does not pair well
    while True:
        client, address = await loop.sock_accept(server)
        await loop.create_task(handler(client, address))
