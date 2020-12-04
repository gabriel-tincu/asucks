"""
    http://www.faqs.org/rfcs/rfc1928.html
"""
from asyncio import Event
from dataclasses import dataclass
from typing import Any, Optional, Set, Union

import enum
import ipaddress
import logging
import socket
import struct

SOCKS5_VER = b"\x05"
RSV = b"\x00"
log = logging.getLogger(__name__)
BUF_SIZE = 2048


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
    conn_not_allowed = b"\x02"
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
    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str]
    port: int
    address_data: bytes


@dataclass
class ServerConfig:
    host: str
    port: int
    username: Optional[str]
    password: Optional[str]


class ProxyConnection:
    def __init__(self, config: Optional[ServerConfig]):
        self.config = config
        self.done = Event()
        self.dst_address: Optional[str] = None

    async def source_read(self, count: int) -> bytes:
        raise NotImplementedError

    async def source_write(self, data: bytes) -> None:
        raise NotImplementedError

    async def destination_write(self, data: bytes) -> None:
        raise NotImplementedError

    async def use_auth_method(self, method: Method) -> None:
        await self.source_write(SOCKS5_VER + method.value)

    async def authenticate(self, methods: Set[Method]) -> None:
        if Method.user_pass in methods and self.config.username and self.config.password:
            await self.use_auth_method(Method.user_pass)
            log.debug("Using username / password authentication")
            await self.check_credentials()
        elif Method.no_auth in methods and not self.config.username and not self.config.password:
            await self.use_auth_method(Method.no_auth)
            log.debug("Using no authentication method")
        else:
            log.error("No usable auth methods found for given config")
            await self.use_auth_method(Method.no_acceptable_methods)
            raise HandshakeError(f"Unknown method {methods}")

    @staticmethod
    async def validate_request_data(connection_info) -> None:
        log.debug("Validating %s", connection_info.address)

    async def process_request(self) -> None:
        try:
            log.debug("Getting supported auth methods")
            methods = await self.get_auth_methods()
            await self.authenticate(methods)
            connection_info = await self.get_destination_info()
            await self.validate_request_data(connection_info)
        except HandshakeError as e:
            log.error("Error during client handshake: %r", e)
            await self.close_all()
            return
        except:  # pylint: disable=bare-except
            log.exception("Unexpected error encountered")
            await self.close_all()
            return
        log.debug(
            "Got host data: %r:%r and command %r",
            connection_info.address,
            connection_info.port,
            connection_info.command,
        )
        if connection_info.command is Command.connect:
            await self.handle_connect(connection_info)
        elif connection_info.command is Command.udp:
            await self.handle_udp(connection_info)
        else:
            await self.send_command_reply(connection_info, CommandReplyStatus.command_not_supported)
            await self.close_all()

    async def send_command_reply(self, connection_info: ConnectionInfo, reply: CommandReplyStatus) -> None:
        # +-----+------+------+------+----------+----------+
        # | VER |  REP |  RSV | ATYP | BND.ADDR | BND.PORT |
        # +-----+------+------+------+----------+----------+
        # |  1  |  1   | X'00'|   1  | Variable |   2      |
        # +-----+------+------+------+----------+----------+
        await self.source_write(SOCKS5_VER + reply + RSV + connection_info.address_type + connection_info.address_data)
        log.debug("Sent command reply %r", reply)

    async def copy_data(self, read: Any, write: Any, name: str):
        while not self.done.is_set():
            data = await read(BUF_SIZE)
            if data == b"":
                self.done.set()
                log.debug("%s: connection closed", name)
                break
            await write(data)
            log.debug("%s: wrote %d bytes", name, len(data))
        log.debug("%s: copy loop closed", name)

    async def create_remote_conn(self, connection_info: ConnectionInfo) -> None:
        raise NotImplementedError

    @property
    def src_address(self) -> str:
        raise NotImplementedError

    async def handle_udp(self, connection_info: ConnectionInfo) -> None:
        pass

    async def handle_connect(self, connection_info: ConnectionInfo) -> None:
        # connect
        try:
            await self.create_remote_conn(connection_info)
            await self.send_command_reply(connection_info, CommandReplyStatus.succeeded)
            await self.create_proxy_loop()
            log.debug("Created proxy loop")
            await self.done.wait()
            log.info("Closing %s and %s", self.src_address, self.dst_address)
        except OSError:
            log.exception("Could not open destination connection to %r:%r", connection_info.address, connection_info.port)
            await self.send_command_reply(connection_info, CommandReplyStatus.general_failure)
        finally:
            await self.close_all()

    async def create_proxy_loop(self) -> None:
        raise NotImplementedError

    async def close_all(self) -> None:
        raise NotImplementedError

    @staticmethod
    def fail_with_empty(data: Union[bytes, str]):
        if not data:
            raise HandshakeError("EOF found, closing connection")

    async def get_auth_methods(self) -> Set[Method]:
        # +-----+----------+----------+
        # | VER | NMETHODS | METHODS  |
        # +-----+----------+----------+
        # |   1 |     1    | 1 to 255 |
        # +-----+----------+----------+
        data = await self.source_read(1)
        self.fail_with_empty(data)
        if data != SOCKS5_VER:
            raise HandshakeError(f"Socks version {data[0]} not supported")
        log.debug("Read version byte")
        data = await self.source_read(1)
        self.fail_with_empty(data)
        method_count = int(data[0])
        data = await self.source_read(method_count)
        methods = set()
        if len(data) < method_count:
            # version, count, then one byte each method
            raise HandshakeError("Not enough data to identify methods")
        for i in range(method_count):
            filtered = {m for m in Method if data[i:i + 1] == m.value}
            if filtered:
                methods = methods.union(filtered)
        log.debug("Got connection methods: %r", methods)
        if not methods:
            raise HandshakeError("No viable methods found")
        return methods

    async def check_credentials(self) -> None:
        # https://tools.ietf.org/html/rfc1929
        user_auth_version = await self.source_read(1)
        if user_auth_version != b"\x01":
            await self.source_write(b"\x01\x01")
            raise HandshakeError(f"Faulty user auth version: {user_auth_version}")
        user_len = await self.source_read(1)
        if user_len == b"":
            await self.source_write(b"\x01\x01")
            raise HandshakeError("Missing user len")
        user_len, = struct.unpack("B", user_len)
        user = await self.source_read(user_len)
        if len(user) != user_len:
            await self.source_write(b"\x01\x01")
            raise HandshakeError("Faulty user len")
        user = user.decode()
        pass_len = await self.source_read(1)
        if pass_len == b"":
            await self.source_write(b"\x01\x01")
            raise HandshakeError("Missing pass len")
        pass_len, = struct.unpack("B", pass_len)
        password = await self.source_read(pass_len)
        if len(password) != pass_len:
            await self.source_write(b"\x01\x01")
            raise HandshakeError("Faulty password len")
        password = password.decode()
        if not await self.auth_ok(user, password):
            await self.source_write(b"\x01\x01")
            raise HandshakeError("Invalid username and/or password")
        await self.source_write(b"\x01\x00")

    async def auth_ok(self, username: str, password: str) -> bool:
        log.info("Performing local credential validation")
        return username == self.config.username and password == self.config.password

    async def get_destination_info(self) -> ConnectionInfo:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        data = await self.source_read(4)
        self.fail_with_empty(data)
        if data[0:1] != SOCKS5_VER:
            raise HandshakeError(f"Invalid protocol version: {data[0]}")
        try:
            command = Command(data[1:2])
        except ValueError as e:
            raise HandshakeError("Unknown command") from e
        if not data[2:3] == RSV:
            raise HandshakeError(f"Reserved byte should be 0 and is: {data[2]}")
        try:
            address_type = AddressType(data[3:4])
        except ValueError as e:
            raise HandshakeError(f"Invalid address type: {data[3]}") from e
        # ipv4
        if address_type is AddressType.ipv4:
            log.debug("Parsing IPV4 addr type")
            address_bytes = await self.source_read(4)
            if len(address_bytes) < 4:
                raise HandshakeError("IPV4 bytes not fully read")
            ip_address = ipaddress.ip_address(address_bytes)
            port_bytes = await self.source_read(2)
            if len(port_bytes) < 2:
                raise HandshakeError("port bytes not fully read")
            port, = struct.unpack(">H", port_bytes)
        elif address_type is AddressType.ipv6:
            log.debug("Parsing IPV6 addr type")
            address_bytes = await self.source_read(16)
            if len(address_bytes) < 16:
                raise HandshakeError("IPV6 bytes not fully read")
            ip_address = ipaddress.ip_address(address_bytes)
            port_bytes = await self.source_read(2)
            if len(port_bytes) < 2:
                raise HandshakeError("port bytes not fully read")
            port, = struct.unpack(">H", port_bytes)
        elif address_type is AddressType.fqdn:
            log.debug("Parsing FQDN addr type")
            address_len_byte = await self.source_read(1)
            self.fail_with_empty(address_len_byte)
            address_len, = struct.unpack("B", address_len_byte)
            address_str = await self.source_read(address_len)
            if len(address_str) < address_len:
                raise HandshakeError("FQDN bytes not fully read")
            address_bytes = address_len_byte + address_str
            port_bytes = await self.source_read(2)
            if len(port_bytes) < 2:
                raise HandshakeError("port bytes not fully read")
            port, = struct.unpack(">H", port_bytes)
            address_info = socket.getaddrinfo(address_str, None)
            if not address_info:
                raise HandshakeError(f"Could not decode address info from {data}")
            ip_address = address_info[0][-1][0]
        else:
            raise HandshakeError(f"Invalid address type: {address_type}")
        self.dst_address = ip_address
        resp = ConnectionInfo(
            address_type=address_type,
            address=ip_address,
            port=port,
            command=command,
            address_data=address_bytes + port_bytes,
        )
        log.debug("Using host %r and port %r", ip_address, port)
        return resp
