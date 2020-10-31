import asyncio
import enum
from typing import Optional, List


class ConnectionState(str, enum.Enum):
    init = "init"
    # get the version number, method count and methods
    get_version = "get_version"
    # either skip through for no auth or do a user / pass auth or something else entirely
    authenticate_start = "authenticate_start"
    authenticate_check_creds = "authenticate_check_creds"
    authenticate_succeeded = "authenticate_succeeded"
    failed = "failed"
    proxy = "proxy"
    closing = "closing"


class SocksDestinationProtocol(asyncio.Protocol):
    def __init__(self, src_transport: asyncio.transports.Transport):
        self.src_transport = src_transport
        self.dst_transport: Optional[asyncio.transports.Transport] = None

    def connection_made(self, transport: asyncio.transports.Transport) -> None:
        self.dst_transport = transport

    def data_received(self, data):
        print(f"Data received from dst {len(data)}")
        self.src_transport.write(data)

    def connection_lost(self, exc):
        print("The destination client closed the connection")


class SocksProxyServerProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.auth_methods: List[int] = []
        self.fail_reason: Optional[str] = None
        self.state: ConnectionState = ConnectionState.init
        self.peername: Optional[str] = None
        self.client_transport: Optional[asyncio.transports.Transport] = None
        self.proxy_transport: Optional[asyncio.transports.Transport] = None

    def connection_made(self, transport: asyncio.transports.Transport) -> None:
        self.peername = transport.get_extra_info('peername')
        self.state = ConnectionState.get_version
        print('Connection from {}'.format(self.peername))
        self.client_transport = transport

    def get_version_and_methods(self, data: bytes) -> None:
        version = int(data[0])
        # socks5 only
        if version != 5:
            self.state = ConnectionState.failed
            self.fail_reason = f"Socks version {version} not supported"
            return None
        if len(data) < 2:
            # version, method count, at least one method
            self.state = ConnectionState.failed
            self.fail_reason = "Not enough data to identify method count"
            return None
        method_count = int(data[1])
        if len(data) < method_count + 2:
            # version, count, then one byte each method
            self.state = ConnectionState.failed
            self.fail_reason = "Not enough data to identify methods"
            return None
        for i in range(method_count):
            self.auth_methods.append(int(data[2+i]))
        self.state = ConnectionState.authenticate_start
        print(f"Got connection methods {self.auth_methods}")

    def data_received(self, data: bytes) -> None:
        print("Data received: {!r}".format(data))
        while self.state is not ConnectionState.closing:
            if self.state == ConnectionState.get_version:
                print("get_version")
                self.get_version_and_methods(data)
            if self.state == ConnectionState.authenticate_start:
                print("auth_start")
                for method in self.auth_methods:
                    print(f"Authenticating for method {method}")
                    if method == 0:
                        self.use_no_auth()
                    elif method == 2:
                        self.use_user_auth()
                    else:
                        print(f"Unknown method {method}")
                        self.state = ConnectionState.failed
                break
            if self.state == ConnectionState.authenticate_check_creds:
                print("auth_check_creds")
                self.check_credentials(data)
                break
            if self.state == ConnectionState.authenticate_succeeded:
                pass

    def get_dest_info(self, data) -> None:
        pass

    def use_no_auth(self) -> None:
        # version + no auth
        self.client_transport.write(b'\x05\x00')
        self.state = ConnectionState.authenticate_succeeded

    def use_user_auth(self) -> None:
        # version + user / pass auth
        self.client_transport.write(b'\x05\x02')
        self.state = ConnectionState.authenticate_check_creds

    def check_credentials(self, data: bytes) -> None:
        if not data:
            self.state = ConnectionState.failed
            self.fail_reason = "No data to authenticate with"
            return
        user_auth_version = int(data[0])
        data = data[1:]
        if user_auth_version != 1:
            self.state = ConnectionState.failed
            self.fail_reason = f"Faulty user auth version: {user_auth_version}"
            return
        if len(data) < 1:
            self.state = ConnectionState.failed
            self.fail_reason = "No data to read user len"
            return
        user_len = int(data[0])
        data = data[1:]
        if len(data) < user_len:
            self.state = ConnectionState.failed
            self.fail_reason = "No data to read user"
            return
        user = data[:user_len].decode()
        data = data[user_len:]
        if len(data) < 1:
            self.state = ConnectionState.failed
            self.fail_reason = "No data to read password len"
            return
        pass_len = int(data[0])
        data = data[1:]
        if len(data) < pass_len:
            self.state = ConnectionState.failed
            self.fail_reason = "No data to read password"
            return
        password = data[:pass_len].decode()
        # TODO -> auth code here
        # user auth succeeded
        self.client_transport.write(b"\x01\x00")
        print(f"Pretending {user}:{password} are ok")
        self.state = ConnectionState.authenticate_succeeded

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            print(exc)
        self.state = ConnectionState.closing
        print(f"closing down {self.peername}")


async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SocksProxyServerProtocol(), "0.0.0.0", 9999)
    addr = server.sockets[0].getsockname()
    print(f"serving on {addr}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
