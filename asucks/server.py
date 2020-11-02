"""
    http://www.faqs.org/rfcs/rfc1928.html
"""
from asyncio.streams import StreamReader, StreamWriter
from dataclasses import dataclass
from typing import Optional, Set

import aiohttp
import asyncio
# pylint: disable=import-error
import click
# pylint: enable=import-error
import enum
import ipaddress
import json
import logging
import socket
import struct

SOCKS5_VER = b"\x05"
RSV = b"\x00"
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


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


class HandshakeError(Exception):
    pass


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
    username: Optional[str]
    password: Optional[str]
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
        if Method.user_pass in methods and self.config.username and self.config.password:
            await self.use_auth_method(Method.user_pass)
            log.info("Using username / password authentication")
            await self.check_credentials()
        elif Method.no_auth in methods and not self.config.username and not self.config.password:
            await self.use_auth_method(Method.no_auth)
            log.info("Using no authentication method")
        else:
            log.error("No usable auth methods found for given config")
            await self.use_auth_method(Method.no_acceptable_methods)
            raise HandshakeError(f"Unknown method {methods}")

    @staticmethod
    async def validate_request_data(connection_info) -> bool:
        log.info("Validating %s", connection_info.address)
        return True

    async def process_request(self) -> None:
        try:
            log.info("get_version")
            methods = await self.get_auth_methods()
            await self.authenticate(methods)
            connection_info = await self.get_dest_info()
            if not await self.validate_request_data(connection_info):
                log.error("Could not validate connection info")
                # TODO -> close the stream here
        except HandshakeError as e:
            log.error("Error during client handshake: %r", e)
            await self.close_all()
            return
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

    @staticmethod
    async def copy_data(src: StreamReader, dst: StreamWriter, done: asyncio.Event, name: str):
        while True:
            data = await src.read(2048)
            if src.at_eof():
                done.set()
                log.info("%s: connection closed", name)
                break
            if done.is_set():
                log.info("%s: connection terminated, writing remaining data and bailing", name)
                dst.write(data)
                break
            dst.write(data)
            log.info("%s: wrote %d bytes", name, len(data))

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
                self.copy_data(dst=self.writer, src=self.dst_reader, done=event, name=f"{dst_addr} -> {src_addr}")
            )
            self.loop.create_task(
                self.copy_data(dst=self.dst_writer, src=self.reader, done=event, name=f"{src_addr} -> {dst_addr}")
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
            log.info("Closing connection to %r", wr.get_extra_info("peername"))
            wr.write_eof()
            await wr.drain()
            wr.close()
            await wr.wait_closed()

    async def get_auth_methods(self) -> Set[Method]:
        data = await self.reader.read(1)
        if not data or data != SOCKS5_VER:
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
            log.error("Got %r, %r", data[i], type(data[i]))
            filtered = {m for m in Method if struct.pack("B", data[i]) == m.value}
            if filtered:
                methods = methods.union(filtered)
        log.info("Got connection methods: %r", methods)
        return methods

    async def check_credentials(self) -> None:
        # https://tools.ietf.org/html/rfc1929
        user_auth_version = await self.reader.read(1)
        if user_auth_version != b"\x01":
            self.writer.write(b"\x01\x01")
            raise HandshakeError("Faulty user auth version: %r", user_auth_version)
        user_len, = struct.unpack("B", await self.reader.read(1))
        user = (await self.reader.read(user_len)).decode()
        pass_len, = struct.unpack("B", await self.reader.read(1))
        password = (await self.reader.read(pass_len)).decode()
        if pass_len != len(password) or user_len != len(user):
            self.writer.write(b"\x01\x01")
            raise HandshakeError("Username / Password sizes do not match")
        if not await self.auth_ok(user, password):
            self.writer.write(b"\x01\x01")
            raise HandshakeError("Invalid username and/or password")
        self.writer.write(b"\x01\x00")

    async def auth_ok(self, username: str, password: str) -> bool:
        if not self.config.validator:
            log.info("Performing local credential validation")
            return username == self.config.username and password == self.config.password
        else:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "type": "external_auth",
                    "username": username,
                    "password": password,
                }
                async with session.post(self.config.validator, json=payload) as resp:
                    if not resp.ok:
                        log.error("Invalid status code: %r", resp.status)
                        return False
                    try:
                        data = await resp.json()
                        if "decision" not in data or data["decision"] != "authenticated":
                            log.error("Invalid response")
                            return False
                    except json.JSONDecodeError:
                        log.error("Response data is not valid json")
                        return False

        return False

    async def get_dest_info(self) -> ConnectionInfo:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        data = await self.reader.read(4)
        if not bytes(data[0]) != SOCKS5_VER:
            raise HandshakeError(f"Invalid protocol version: {data[0]}")
        try:
            command = Command(struct.pack("B", data[1]))
        except ValueError:
            raise HandshakeError(f"Unknown command")
        if not struct.pack("B", data[2]) == RSV:
            raise HandshakeError(f"Reserved byte should be 0 and is: {data[2]}")
        try:
            addr_type = AddressType(struct.pack("B", data[3]))
        except ValueError:
            raise HandshakeError(f"Invalid address type: {data[3]}")
        # ipv4
        if addr_type is AddressType.ipv4:
            log.info("Parsing IPV4 addr type")
            addr_bytes = await self.reader.read(4)
            ip_addr = str(ipaddress.ip_address(addr_bytes))
            port_bytes = await self.reader.read(2)
            port, = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.ipv6:
            log.info("Parsing IPV6 addr type")
            addr_bytes = await self.reader.read(16)
            ip_addr = str(ipaddress.ip_address(addr_bytes))
            port_bytes = await self.reader.read(2)
            port, = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.fqdn:
            log.info("Parsing FQDN addr type")
            addr_len_byte = await self.reader.read(1)
            addr_len, = struct.unpack("B", addr_len_byte)
            addr_str = await self.reader.read(addr_len)
            addr_bytes = addr_len_byte + addr_str
            port_bytes = await self.reader.read(2)
            port, = struct.unpack(">H", port_bytes)
            addr_info = socket.getaddrinfo(addr_str, None)
            if not addr_info:
                raise HandshakeError(f"Could not decode adddres info from {data}")
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
