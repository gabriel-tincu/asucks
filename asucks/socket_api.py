from asucks.base_server import AddressType, BUF_SIZE, ConnectionInfo, ProxyConnection, ServerConfig
from asyncio import AbstractEventLoop, Event
from typing import Optional

import logging
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
        self.total_transported = 0
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
        data = await self.loop.sock_recv(self.source_socket, count)
        self.total_transported += len(data)
        return data

    def ready_read(self, sock: socket.socket) -> None:
        if sock is self.destination_socket:
            dest = self.source_socket
            src = self.destination_socket
            src_tag = self.dst_address
            dst_tag = self.source_socket
        else:
            dest = self.destination_socket
            src = self.source_socket
            src_tag = self.source_address
            dst_tag = self.dst_address
        while not self.done.is_set():
            data = src.recv(BUF_SIZE)
            dest.sendall(data)
            self.total_transported += len(data)
            log.debug("Sent %d bytes from %s to %s", len(data), src_tag, dst_tag)
            if not data:
                log.debug("EOF read from destination %s", src_tag)
                self.loop.remove_reader(src)
                self.done.set()
                return
            if len(data) < BUF_SIZE:
                log.debug("Read %d bytes instead of %d, waiting to be called again", len(data), BUF_SIZE)
                return

    async def source_write(self, data: bytes):
        self.total_transported += len(data)
        return await self.loop.sock_sendall(self.source_socket, data)

    async def destination_write(self, data: bytes):
        self.total_transported += len(data)
        return await self.loop.sock_sendall(self.destination_socket, data)

    async def close_all(self):
        #  pylint: disable=bare-except
        for sock in [self.source_socket, self.destination_socket]:
            self.loop.remove_reader(sock)
            try:
                sock.close()
            except:
                pass
        log.info("Closed both source and destination sockets, shuffled total %d bytes", self.total_transported)

    async def create_remote_conn(self, connection_info: ConnectionInfo) -> None:
        log.debug("Creating %r socket", connection_info.address_type)
        if connection_info.address_type is not AddressType.ipv6:
            self.destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.destination_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        if connection_info.address_type is AddressType.fqdn:
            addr = connection_info.address
        else:
            addr = connection_info.address.compressed
        await self.loop.sock_connect(self.destination_socket, (addr, connection_info.port))

    async def create_proxy_loop(self):
        self.loop.add_reader(self.destination_socket, self.ready_read, self.destination_socket)
        self.loop.add_reader(self.source_socket, self.ready_read, self.source_socket)


class SocketServer:
    def __init__(self, config: ServerConfig, loop: AbstractEventLoop, closing: Optional[Event] = None):
        self.config = config
        self.loop = loop
        self.closing = closing or Event()
        self.server: Optional[socket] = None

    def bind(self):
        # pylint: disable=no-member
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.config.host, self.config.port))
        sock.listen(10)
        sock.setblocking(False)
        log.info("Bound to (%r, %r)", self.config.host, self.config.port)
        # pylint: enable=no-member
        return sock

    async def run_server(self) -> None:
        self.server = self.bind()
        while not self.closing.is_set():
            client, address = await self.loop.sock_accept(self.server)
            client.setblocking(False)
            log.info("Handling connection from %r", address)
            self.loop.create_task(self.conn_handler(client, address))
        log.info("Server closing down")
        if self.server:
            try:
                self.server.close()
            except socket.error as e:
                log.error("Error closing down server: %r", e)

    async def conn_handler(self, client: socket.socket, address: str) -> None:
        conn = SocketProxyConnection(
            source_socket=client,
            source_address=address,
            loop=self.loop,
            config=self.config,
        )
        await conn.process_request()
        log.debug("Done handling requests for %s", address)

    def close(self):
        self.closing.set()
