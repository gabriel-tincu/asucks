from asucks.base_server import (
    AddressType, BUF_SIZE, Command, CommandReplyStatus, ConnectionInfo, HandshakeError, Method, RSV, ServerConfig,
    SOCKS5_VER
)
from threading import Event, Thread
from typing import Any, List, Optional, Set, Union

import click
import ipaddress
import json
import logging
import requests
import select
import socket
import ssl
import struct
import time

log = logging.getLogger(__name__)


class SocketProxyConnection:
    # pylint: disable=super-init-not-called
    def __init__(
        self,
        source_socket: socket.socket,
        source_address: str,
        config: ServerConfig,
    ) -> None:
        self.config = config
        self.destination_socket: Optional[socket.socket] = None
        self.source_socket = source_socket
        self.source_address = source_address
        self.done = Event()

    def handle_connect(self, connection_info: ConnectionInfo) -> None:
        # connect
        try:
            log.info("Creating %r socket", connection_info.address_type)
            self.create_remote_conn(connection_info)
            log.info("Sending connect reply")
            self.send_command_reply(connection_info, CommandReplyStatus.succeeded)
            log.info("Creating proxy loop")
            self.create_proxy_loop()
            log.debug("Created proxy loop")
            self.done.wait()
            log.info("Closing %s and %s", self.src_address, self.dst_address)
        except OSError:
            log.exception("Could not open destination connection to %r:%r", connection_info.address, connection_info.port)
            self.send_command_reply(connection_info, CommandReplyStatus.general_failure)
        finally:
            self.close_all()

    @staticmethod
    def fail_with_empty(data: Union[bytes, str]):
        if not data:
            raise HandshakeError("EOF found, closing connection")

    def get_auth_methods(self) -> Set[Method]:
        data = self.source_read(1)
        if not data or data != SOCKS5_VER:
            raise HandshakeError(f"Socks version {data[0]} not supported")
        log.debug("Read version byte")
        data = self.source_read(1)
        self.fail_with_empty(data)
        method_count = int(data[0])
        data = self.source_read(method_count)
        methods = set()
        if len(data) < method_count:
            # version, count, then one byte each method
            raise HandshakeError("Not enough data to identify methods")
        for i in range(method_count):
            filtered = {m for m in Method if struct.pack("B", data[i]) == m.value}
            if filtered:
                methods = methods.union(filtered)
        log.debug("Got connection methods: %r", methods)
        return methods

    async def check_credentials(self) -> None:
        # https://tools.ietf.org/html/rfc1929
        user_auth_version = self.source_read(1)
        self.fail_with_empty(user_auth_version)
        if user_auth_version != b"\x01":
            self.source_write(b"\x01\x01")
            raise HandshakeError(f"Faulty user auth version: {user_auth_version}")
        user_len = self.source_read(1)
        self.fail_with_empty(user_len)
        user_len, = struct.unpack("B", user_len)
        user = (self.source_read(user_len)).decode()
        self.fail_with_empty(user)
        pass_len = self.source_read(1)
        self.fail_with_empty(pass_len)
        pass_len, = struct.unpack("B", pass_len)
        password = (self.source_read(pass_len)).decode()
        if pass_len != len(password) or user_len != len(user):
            self.source_write(b"\x01\x01")
            raise HandshakeError("Username / Password sizes do not match")
        if not self.auth_ok(user, password):
            self.source_write(b"\x01\x01")
            raise HandshakeError("Invalid username and/or password")
        self.source_write(b"\x01\x00")

    def auth_ok(self, username: str, password: str) -> bool:
        if not self.config.validator:
            log.info("Performing local credential validation")
            return username == self.config.username and password == self.config.password

        if self.config.ca_file is not None:
            ssl_context = ssl.create_default_context(capath=self.config.ca_file)
            payload = {
                "type": "external_auth",
                "username": username,
                "password": password,
            }
            resp = requests.post(self.config.validator, json=payload, ssl=ssl_context)
            if not resp.ok:
                log.error("Invalid status code: %r", resp.status_code)
                return False
            try:
                data = resp.json()
                if "decision" not in data or data["decision"] != "authenticated":
                    log.error("Invalid response")
                    return False
            except json.JSONDecodeError:
                log.error("Response data is not valid json")
                return False

        return False

    def get_dest_info(self) -> ConnectionInfo:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        data = self.source_read(4)
        self.fail_with_empty(data)
        if struct.pack("B", data[0]) != SOCKS5_VER:
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
            addr_bytes = self.source_read(4)
            self.fail_with_empty(addr_bytes)
            ip_addr = ipaddress.ip_address(addr_bytes)
            port_bytes = self.source_read(2)
            self.fail_with_empty(port_bytes)
            port, = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.ipv6:
            log.info("Parsing IPV6 addr type")
            addr_bytes = self.source_read(16)
            self.fail_with_empty(addr_bytes)
            ip_addr = ipaddress.ip_address(addr_bytes)
            port_bytes = self.source_read(2)
            self.fail_with_empty(port_bytes)
            port, = struct.unpack(">H", port_bytes)
        elif addr_type is AddressType.fqdn:
            log.info("Parsing FQDN addr type")
            addr_len_byte = self.source_read(1)
            self.fail_with_empty(addr_len_byte)
            addr_len, = struct.unpack("B", addr_len_byte)
            addr_str = self.source_read(addr_len)
            self.fail_with_empty(addr_str)
            addr_bytes = addr_len_byte + addr_str
            port_bytes = self.source_read(2)
            port, = struct.unpack(">H", port_bytes)
            addr_info = socket.getaddrinfo(addr_str, None)
            if not addr_info:
                raise HandshakeError(f"Could not decode adddres info from {data}")
            ip_addr = addr_info[0][-1][0]
        else:
            raise HandshakeError(f"Invalid address type: {addr_type}")
        self.dst_address = ip_addr
        resp = ConnectionInfo(
            address_type=addr_type,
            address=ip_addr,
            port=port,
            command=command,
            address_data=addr_bytes + port_bytes,
        )
        log.info("Using host %r and port %r", ip_addr, port)
        return resp

    def use_auth_method(self, method: Method) -> None:
        self.source_write(SOCKS5_VER + method.value)

    def authenticate(self, methods: Set[Method]) -> None:
        if Method.user_pass in methods and self.config.username and self.config.password:
            self.use_auth_method(Method.user_pass)
            log.info("Using username / password authentication")
            self.check_credentials()
        elif Method.no_auth in methods and not self.config.username and not self.config.password:
            self.use_auth_method(Method.no_auth)
            log.info("Using no authentication method")
        else:
            log.error("No usable auth methods found for given config")
            self.use_auth_method(Method.no_acceptable_methods)
            raise HandshakeError(f"Unknown method {methods}")

    @staticmethod
    def validate_request_data(connection_info) -> None:
        log.info("Validating %s", connection_info.address)

    def process_request(self) -> None:
        try:
            log.debug("Getting supported auth methods")
            methods = self.get_auth_methods()
            self.authenticate(methods)
            connection_info = self.get_dest_info()
            self.validate_request_data(connection_info)
        except HandshakeError as e:
            log.error("Error during client handshake: %r", e)
            self.close_all()
            return
        log.info(
            "Got host data: %r:%r and command %r",
            connection_info.address,
            connection_info.port,
            connection_info.command,
        )
        if connection_info.command is Command.connect:
            self.handle_connect(connection_info)
        else:
            self.send_command_reply(connection_info, CommandReplyStatus.command_not_supported)
            self.close_all()

    def send_command_reply(self, connection_info: ConnectionInfo, reply: CommandReplyStatus) -> None:
        # +-----+------+------+------+----------+----------+
        # | VER |  REP |  RSV | ATYP | BND.ADDR | BND.PORT |
        # +-----+------+------+------+----------+----------+
        # |  1  |  1   | X'00'|   1  | Variable |   2      |
        # +-----+------+------+------+----------+----------+
        self.source_write(SOCKS5_VER + reply + RSV + connection_info.address_type + connection_info.address_data)
        log.debug("Sent command reply %r", reply)

    @property
    def src_address(self):
        return self.source_address[0]

    def source_read(self, count: int) -> bytes:
        return self.source_socket.recv(count)

    def source_write(self, data: bytes):
        self.source_socket.sendall(data)

    def destination_write(self, data: bytes):
        return self.destination_socket.sendall(data)

    def close_all(self):
        #  pylint: disable=bare-except
        try:
            self.source_socket.close()
        except:
            pass
        try:
            self.destination_socket.close()
        except:
            pass
        log.info("Closed both source and dest socket")

    def create_remote_conn(self, connection_info: ConnectionInfo) -> None:
        if connection_info.address_type is not AddressType.ipv6:
            self.destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.destination_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        if connection_info.address_type is AddressType.fqdn:
            addr = connection_info.address
        else:
            addr = connection_info.address.compressed
        self.destination_socket.setblocking(True)
        self.destination_socket.connect((addr, connection_info.port))

    def create_proxy_loop(self):
        while not self.done.is_set():
            sock = None
            if can_read([self.source_socket, self.destination_socket], self.destination_socket):
                sock = self.destination_socket
            if can_read([self.source_socket, self.destination_socket], self.source_socket):
                sock = self.source_socket
            if sock is None:
                time.sleep(0.2)
                continue
            if sock is self.destination_socket:
                dest = self.source_socket
                src = self.destination_socket
                src_tag = self.dst_address
                dest_tag = self.src_address
            else:
                dest = self.destination_socket
                src = self.source_socket
                src_tag = self.source_address
                dest_tag = self.dst_address
            log.info("Starting to read from %r", src_tag)
            data = src.recv(BUF_SIZE)
            dest.sendall(data)
            if not data:
                log.info("EOF read from dest %s", dest_tag)
                self.done.set()


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
    sock.setblocking(True)
    log.info("Bound to (%r, %r)", host, port)
    # pylint: enable=no-member
    return sock


def run_server(server: socket.socket, handler: Any) -> None:
    # I would have used callable, but having an async signature does not pair well
    while True:
        try:
            client, address = server.accept()
            log.info("Handling connection from %r", address)
            Thread(target=handler, args=(client, address)).start()
        except Exception as e:
            log.error("Error accepting client connection: %r", e)


def run(
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

    def handler(client: socket.socket, address: str):
        conn = SocketProxyConnection(
            source_socket=client,
            source_address=address,
            config=config,
        )
        conn.process_request()
        log.info("Done handling requests for %s", address)

    server = server_bind_socket(host=config.host, port=config.port)
    run_server(server=server, handler=handler)


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
    run(
        username=username,
        host=host,
        port=port,
        password=password,
        validator=validator,
        cafile=cafile,
    )


# pylint: disable=no-value-for-parameter
if __name__ == "__main__":
    main()
