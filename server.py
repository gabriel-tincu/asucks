"""
    http://www.faqs.org/rfcs/rfc1928.html
"""
import asyncio
import enum
import ipaddress
import logging
import socket
import struct

from asyncio.streams import StreamWriter, StreamReader
from dataclasses import dataclass
from typing import Optional, Set

SOCKS5_VER = b"\x05"
RSV = b"\x00"
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class HandshakeError(Exception):
    pass


class AddressType(bytes, enum.Enum):
    ipv4 = b"\x01"
    fqdn = b"\x03"
    ipv6 = b"\x04"


class Method(bytes, enum.Enum):
    no_auth = b"\x00"
    gssapi = b"\x01"
    user_pass = b"\x02"
    no_acceptable_methods = b"\xff"


class Command(bytes, enum.Enum):
    connect = b"\x01"
    bind = b"\x02"
    udp = b"\x03"


class CommandReplyStatus(bytes, enum.Enum):
    succeeded = b"\x00"
    general_failure = b"\x01"
    conn_not_allower = b"\x02"
    network_unreachable = b"\x03"
    host_unreachable = b"\x04"
    connection_refused = b"\x05"
    ttl_expired = b"\x06"
    command_not_supported = b"\x07"
    address_type_unsupported = b"\x08"


@dataclass
class ConnectionInfo:
    command: Command
    address_type: AddressType
    address: str
    port: int
    address_data: bytes


@dataclass
class ServerConfig:
    host: str
    port: int
    username: str
    password: str
    validator: Optional[str]
    ca_file: Optional[str]


class ProxyConnection:
    def __init__(self, reader: StreamReader, writer: StreamWriter, config: ServerConfig):
        log.info("Got reader: %r and writer %r", reader, writer)
        self.config = config
        self.reader = reader
        self.writer = writer
        self.dst_reader: Optional[StreamReader] = None
        self.dst_writer: Optional[StreamWriter] = None
        self.loop = asyncio.get_running_loop()

    async def use_auth_method(self, method: Method) -> None:
        self.writer.write(SOCKS5_VER + method.value)
        await self.writer.drain()

    async def authenticate(self, methods: Set[Method]) -> None:
        if Method.user_pass in methods:
            await self.use_auth_method(Method.user_pass)
            log.info("auth_check_creds")
            await self.check_credentials()
        elif Method.no_auth in methods:
            await self.use_auth_method(Method.no_auth)
            log.info("Using no auth method")
        else:
            log.error("No usable auth methods found")
            await self.use_auth_method(Method.no_acceptable_methods)
            raise HandshakeError(f"Unknown method {methods}")

    @staticmethod
    async def validate_request_data(connection_info) -> bool:
        log.info("Validating %s", connection_info.address)
        return True

    async def process_request(self) -> None:
        log.info("get_version")
        methods = await self.get_auth_methods()
        await self.authenticate(methods)
        connection_info = await self.get_dest_info()
        if not await self.validate_request_data(connection_info):
            log.error("Could not validate connection info")
            # TODO -> close the stream here
        log.info(
            "Got host data: %r:%r and command %r",
            connection_info.address,
            connection_info.port,
            connection_info.command,
        )
        if connection_info.command is Command.connect:
            await self.handle_connect(connection_info)
        else:
            await self.send_command_reply(connection_info, CommandReplyStatus.command_not_supported)
            await self.close_all()

    async def send_command_reply(self, connection_info: ConnectionInfo, reply: CommandReplyStatus) -> None:
        # +-----+------+------+------+----------+----------+
        # | VER |  REP |  RSV | ATYP | BND.ADDR | BND.PORT |
        # +-----+------+------+------+----------+----------+
        # |  1  |  1   | X'00'|   1  | Variable |   2      |
        # +-----+------+------+------+----------+----------+
        self.writer.write(SOCKS5_VER + reply + RSV + connection_info.address_type + connection_info.address_data)
        await self.writer.drain()

    async def copy_data(self, src: StreamReader, dst: StreamWriter, done: asyncio.Event):
        while True:
            data = await src.read(2048)
            if data == b"" or src.at_eof():
                done.set()
                log.info("Source connection closed")
                break
            if done.is_set():
                log.info("Connection terminated, writing remaining data and bailing")
                dst.write(data)
                break
            dst.write(data)
            log.info("Wrote %d bytes to %s", len(data), self.writer.get_extra_info("peername"))

    async def handle_connect(self, connection_info: ConnectionInfo) -> None:
        # connect
        try:
            self.dst_reader, self.dst_writer = await asyncio.open_connection(
                connection_info.address, connection_info.port, loop=self.loop
            )

            await self.send_command_reply(connection_info, CommandReplyStatus.succeeded)
            src_addr = self.writer.get_extra_info("peername")
            dst_addr = connection_info.address
            event = asyncio.Event()
            self.loop.create_task(
                self.copy_data(dst=self.writer, src=self.dst_reader, done=event), name=f"{dst_addr} -> {src_addr}"
            )
            self.loop.create_task(
                self.copy_data(dst=self.dst_writer, src=self.reader, done=event), name=f"{src_addr} -> {dst_addr}"
            )
            await event.wait()
        except OSError:
            log.exception("Could not open destination connection to %r:%r", connection_info.address, connection_info.port)
            await self.send_command_reply(connection_info, CommandReplyStatus.general_failure)
        finally:
            await self.close_all()

    async def close_all(self):
        for wr in [self.writer, self.dst_writer]:
            if wr is None:
                continue
            wr.write_eof()
            await wr.drain()
            wr.close()
            await wr.wait_closed()

    async def get_auth_methods(self) -> Set[Method]:
        data = await self.reader.read(1)
        if not data or data[0] != SOCKS5_VER:
            raise HandshakeError(f"Socks version {data[0]} not supported")
        log.info("Read version byte")
        data = await self.reader.read(1)
        method_count = int(data[0])
        data = await self.reader.read(method_count)
        methods = set()
        if len(data) < method_count:
            # version, count, then one byte each method
            raise HandshakeError("Not enough data to identify methods")
        for i in range(method_count):
            filtered = {m for m in Method if data[i] == m.value}
            if filtered:
                methods = methods.union(filtered)
        log.info("Got connection methods: %r", methods)
        return methods

    async def check_credentials(self) -> None:
        user_auth_version, = struct.unpack("B", await self.reader.read(1))
        if user_auth_version != 1:
            raise HandshakeError(f"Faulty user auth version: {user_auth_version}")
        user_len, = struct.unpack("B", await self.reader.read(1))
        user = (await self.reader.read(user_len)).decode()
        pass_len, = struct.unpack("B", await self.reader.read(1))
        password = (await self.reader.read(pass_len)).decode
        # TODO -> auth code here
        # user auth succeeded
        self.writer.write(b"\x01\x00")
        log.info("Pretending %s:%s are ok", user, password)

    async def get_dest_info(self) -> ConnectionInfo:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        data = await self.reader.read(4)
        if not data[0] != SOCKS5_VER:
            raise HandshakeError(f"Invalid protocol version: {data[0]}")
        try:
            command = Command(data[1])
        except ValueError:
            raise HandshakeError(f"Unknown command")
        if not data[2] == RSV:
            raise HandshakeError(f"Reserved byte should be 0 and is: {data[2]}")
        try:
            addr_type = AddressType(data[3])
        except ValueError:
            raise HandshakeError(f"Invalid address type: {data[3]}")
        # ipv4
        if addr_type is AddressType.ipv4:
            log.info("Parsing IPV4 addr type")
            addr_bytes = await self.reader.read(4)
            ip_addr = str(ipaddress.ip_address(addr_bytes))
            port_bytes = await self.reader.read(2)
            port = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.ipv6:
            log.info("Parsing IPV6 addr type")
            addr_bytes = await self.reader.read(16)
            ip_addr = str(ipaddress.ip_address(addr_bytes))
            port_bytes = await self.reader.read(2)
            port = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.fqdn:
            log.info("Parsing FQDN addr type")
            addr_len_byte = await self.reader.read(1)
            addr_len, _ = struct.unpack("B", addr_len_byte)
            addr_str = await self.reader.read(addr_len)
            addr_bytes = addr_len_byte + addr_str
            port_bytes = await self.reader.read(2)
            port, _ = struct.unpack(">H", port_bytes)
            addr_info = socket.getaddrinfo(addr_str, None)
            if not addr_info:
                raise HandshakeError(f"Could not decode adddres info from {data}")
            # take the first element of the tuple
            ip_addr = addr_info[0][-1][0]
        else:
            raise HandshakeError(f"Invalid address type: {addr_type}")
        resp = ConnectionInfo(
            address_type=addr_type,
            address=ip_addr,
            port=port,
            address_data=addr_bytes + port_bytes,
            command=command,
        )
        log.info("Using host %r and port %r", ip_addr, port)
        return resp


def conn_factory(config: ServerConfig):
    async def proxy(reader: StreamReader, writer: StreamWriter) -> None:
        conn = ProxyConnection(reader=reader, writer=writer, config=config)
        await conn.process_request()

    return proxy


async def main():
    host = "0.0.0.0"
    port = 1080
    username = "foo"
    password = "foopass"
    validator = None
    cafile = None
    config = ServerConfig(
        host=host,
        port=int(port),
        username=username,
        password=password,
        validator=validator,
        ca_file=cafile,
    )
    loop = asyncio.get_running_loop()
    server = await asyncio.start_server(conn_factory(config), host=config.host, port=config.port, loop=loop)
    addr = server.sockets[0].getsockname()
    print(f"serving on {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
