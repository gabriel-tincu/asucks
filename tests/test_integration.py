from aiohttp_socks import ProxyConnector
from asucks.base_server import run as stream_run
from asucks.socket_api import run as socker_run

import aiohttp
import asyncio
import pytest
import random

pytestmark = pytest.mark.asyncio


async def test_proxied_http_calls():
    loop = asyncio.get_running_loop()
    port = random.randint(40000, 60000)
    coro = stream_run(
        username="foo",
        password="foopass",
        host="127.0.0.1",
        port=port,
        cafile=None,
        validator=None,
    )
    task = loop.create_task(coro)
    await asyncio.sleep(0.5)
    connector = ProxyConnector.from_url(f"socks5://foo:foopass@127.0.0.1:{port}")
    async with aiohttp.ClientSession(connector=connector) as session:
        resp = await session.get("http://asdf.com")
        assert resp.ok
    task.cancel()
    port = random.randint(40000, 60000)
    coro = socker_run(
        username="foo",
        password="foopass",
        host="127.0.0.1",
        port=port,
        cafile=None,
        validator=None,
    )
    task = loop.create_task(coro)
    await asyncio.sleep(0.5)
    connector = ProxyConnector.from_url(f"socks5://foo:foopass@127.0.0.1:{port}")
    async with aiohttp.ClientSession(connector=connector) as session:
        resp = await session.get("http://asdf.com")
        assert resp.ok
    task.cancel()
