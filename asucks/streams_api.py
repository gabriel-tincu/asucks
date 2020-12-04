from asucks.base_server import AddressType, ConnectionInfo, ProxyConnection, ServerConfig
from asyncio import AbstractEventLoop, AbstractServer, Event, get_running_loop, open_connection, sleep, start_server
from asyncio.streams import StreamReader, StreamWriter
from typing import Optional

import logging

log = logging.getLogger(__name__)


class StreamsProxyConnection(ProxyConnection):
    def __init__(
        self,
        reader: Optional[StreamReader],
        writer: Optional[StreamWriter],
        config: Optional[ServerConfig],
        loop: Optional[AbstractEventLoop] = None,
    ):
        super().__init__(config)
        log.debug("Got reader: %r and writer %r", reader, writer)
        self.total_transported = 0
        self.reader = reader
        self.writer = writer
        self.dst_reader: Optional[StreamReader] = None
        self.dst_writer: Optional[StreamWriter] = None
        self.loop = loop or get_running_loop()

    async def source_read(self, count: int) -> bytes:
        data = await self.reader.read(count)
        self.total_transported += len(data)
        return data

    async def destination_read(self, count: int) -> bytes:
        data = await self.dst_reader.read(count)
        self.total_transported += len(data)
        return data

    async def source_write(self, data: bytes) -> None:
        self.total_transported += len(data)
        self.writer.is_closing()
        self.writer.write(data)
        await self.writer.drain()

    async def destination_write(self, data: bytes) -> None:
        self.total_transported += len(data)
        self.dst_writer.write(data)
        await self.dst_writer.drain()

    async def create_remote_conn(self, connection_info: ConnectionInfo) -> None:
        if connection_info.address_type is AddressType.fqdn:
            address = connection_info.address
        else:
            address = connection_info.address.exploded
        self.dst_reader, self.dst_writer = await open_connection(address, connection_info.port)

    @property
    def src_address(self) -> str:
        return self.writer.get_extra_info("peername")

    async def create_proxy_loop(self) -> None:
        self.loop.create_task(
            self.copy_data(
                read=self.source_read, write=self.destination_write, name=f"{self.dst_address} -> {self.src_address}"
            )
        )
        self.loop.create_task(
            self.copy_data(
                read=self.destination_read, write=self.source_write, name=f"{self.src_address} -> {self.dst_address}"
            )
        )

    async def close_all(self) -> None:
        for wr in [self.writer, self.dst_writer]:
            if wr is None:
                continue
            log.debug("Closing connection to %r", wr.get_extra_info("peername"))
            wr.write_eof()
            await wr.drain()
            wr.close()
            await wr.wait_closed()
        log.info("Shuffled a total of %d bytes", self.total_transported)


class StreamServer:
    def __init__(self, config: ServerConfig, loop: AbstractEventLoop, closing: Optional[Event]):
        self.config = config
        self.loop = loop
        self.closing = closing
        self.server: Optional[AbstractServer] = None

    async def conn_handler(self, reader: StreamReader, writer: StreamWriter) -> None:
        conn = StreamsProxyConnection(reader=reader, writer=writer, config=self.config)
        await conn.process_request()
        log.info("Done processing request")

    async def run_server(self) -> None:
        self.server = await start_server(self.conn_handler, host=self.config.host, port=self.config.port)
        async with self.server:
            await self.server.start_serving()
            while not self.closing.is_set():
                await sleep(0.5)
        log.info("Closing down server")
        try:
            self.server.close()
        except Exception as e:  # pylint: disable=broad-except
            log.error("Error closing down server: %r", e)

    def close(self):
        self.closing.set()
