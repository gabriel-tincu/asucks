from asucks.base_server import AddressType, BUF_SIZE, ConnectionInfo, ProxyConnection, ServerConfig
from asyncio import AbstractEventLoop, Event, get_running_loop, sleep
from typing import Any, List, Optional

import logging
import select
import socket

log = logging.getLogger(__name__)


class SocketProxyConnection(ProxyConnection):
    # pylint: disable=super-init-not-called
    def __init__(
        self,
        source_socket: socket.socket,
        source_address: str,
        loop: AbstractEventLoop,
        config: ServerConfig,
    ) -> None:
        self.config = config
        self.destination_socket: Optional[socket.socket] = None
        self.source_socket = source_socket
        self.source_address = source_address
        self.loop = loop
        self.done = Event()

    @property
    def src_address(self):
        return self.source_address[0]

    async def source_read(self, count: int) -> bytes:
        while not self.done.is_set():
            if not can_read([self.source_socket, self.destination_socket], self.source_socket):
                log.debug("Source socket not ready for read, waiting")
                await sleep(0.1)
                continue
            return await self.loop.sock_recv(self.source_socket, count)
        log.info("No more data to read from source")
        return b""

    def ready_read(self, sock: socket.socket) -> None:
        if sock is self.destination_socket:
            dest = self.source_socket
            src = self.destination_socket
            src_tag = self.dst_address
        else:
            dest = self.destination_socket
            src = self.source_socket
            src_tag = self.source_address
        if not self.done.is_set():
            read = 0
            while True:
                data = src.recv(BUF_SIZE)
                dest.sendall(data)
                read += len(data)
                if not data:
                    log.debug("Read %d total bytes from %s", read, src_tag)
                    log.info("EOF read from dest")
                    self.loop.remove_reader(src)
                    self.done.set()
                    return
                if len(data) < BUF_SIZE:
                    log.debug("Read %d total bytes from %s", read, src_tag)
                    return
        else:
            log.info("Closing dest sock")
            self.loop.remove_reader(src)

    async def source_write(self, data: bytes):
        return await self.loop.sock_sendall(self.source_socket, data)

    async def destination_write(self, data: bytes):
        return await self.loop.sock_sendall(self.destination_socket, data)

    async def close_all(self):
        #  pylint: disable=bare-except
        try:
            self.loop.remove_reader(self.source_socket)
        except:
            pass
        try:
            self.loop.remove_reader(self.destination_socket)
        except:
            pass
        try:
            self.source_socket.close()
        except:
            pass
        try:
            self.destination_socket.close()
        except:
            pass
        log.info("Closed both source and dest socket")

    async def create_remote_conn(self, connection_info: ConnectionInfo) -> None:
        log.info("Creating %r socket", connection_info.address_type)
        if connection_info.address_type is not AddressType.ipv6:
            self.destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.destination_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        await self.loop.sock_connect(self.destination_socket, (connection_info.address, connection_info.port))

    async def create_proxy_loop(self):
        self.loop.add_reader(self.destination_socket, self.ready_read, self.destination_socket)
        self.loop.add_reader(self.source_socket, self.ready_read, self.source_socket)


def can_read(all_socks: List[socket.socket], target_sock: socket.socket) -> bool:
    all_socks = [s for s in all_socks if s is not None]
    if not all_socks:
        log.error("No socket object defined yet")
        return False
    try:
        reader, _, _ = select.select(all_socks, [], [], 1)
    except select.error as e:
        log.error("Select failed: %r", e)
        return False
    if not reader:
        return False
    for sock in reader:
        if sock is target_sock:
            return True
    return False


def server_bind_socket(host: str, port: int) -> socket:
    # pylint: disable=no-member
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(10)
    sock.setblocking(False)
    log.info("Bound to (%r, %r)", host, port)
    # pylint: enable=no-member
    return sock


async def run_server(server: socket.socket, loop: AbstractEventLoop, handler: Any) -> None:
    # I would have used callable, but having an async signature does not pair well
    while True:
        client, address = await loop.sock_accept(server)
        await loop.create_task(handler(client, address))


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
    loop = get_running_loop()

    async def handler(client: socket.socket, address: str):
        conn = SocketProxyConnection(
            source_socket=client,
            source_address=address,
            loop=loop,
            config=config,
        )
        await conn.process_request()
        log.info("Done handling requests for %s", address)

    server = server_bind_socket(host=config.host, port=config.port)
    await run_server(server=server, loop=loop, handler=handler)
