from aiohttp_socks import ProxyConnector
from asucks.base_server import ServerConfig
from asucks.server import run_main
from asucks.streams_api import StreamServer
from asucks.socket_api import SocketServer

import aiohttp
import asyncio
import pytest
import random

pytestmark = pytest.mark.asyncio


async def test_proxied_http_calls():
    loop = asyncio.get_running_loop()
    port = random.randint(40000, 60000)
    config = ServerConfig(
        username="foo",
        password="foopass",
        host="127.0.0.1",
        port=port,
    )
    task = loop.create_task(run_main(config, False))
    await asyncio.sleep(0.5)
    connector = ProxyConnector.from_url(f"socks5://foo:foopass@127.0.0.1:{port}")
    async with aiohttp.ClientSession(connector=connector) as session:
        resp = await session.get("http://asdf.com")
        assert resp.ok
    task.cancel()
    port = random.randint(40000, 60000)
    config = ServerConfig(
        username="foo",
        password="foopass",
        host="127.0.0.1",
        port=port,
    )
    task = loop.create_task(run_main(config, True))
    await asyncio.sleep(0.5)
    connector = ProxyConnector.from_url(f"socks5://foo:foopass@127.0.0.1:{port}")
    async with aiohttp.ClientSession(connector=connector) as session:
        resp = await session.get("http://asdf.com")
        assert resp.ok
    task.cancel()


async def test_closes():
    config = ServerConfig(
        username="foo",
        password="foopass",
        host="127.0.0.1",
        port=random.randint(40000, 60000),
    )
    loop = asyncio.get_running_loop()
    server = StreamServer(config=config, loop=loop)
    task = loop.create_task(server.run_server())
    await asyncio.sleep(0.5)
    assert server.running, "Server should be running"
    server.close()
    await asyncio.sleep(0.5)
    assert not server.running, "Server should not be running"
    assert task.done()
    # i should probably update the close / start methods on the socket server as well
    server = SocketServer(config=config, loop=loop)
    task = loop.create_task(server.run_server())
    await asyncio.sleep(0.5)
    assert server.running, "Server should be running"
    task.cancel()
    server.close()
    await asyncio.sleep(0.5)
    assert not server.running, "Server should not be running"
    assert task.done()
