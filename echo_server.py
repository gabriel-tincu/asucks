import asyncio
from asyncio.streams import StreamReader, StreamWriter


async def echo(reader: StreamReader, writer: StreamWriter) -> None:
    data = await reader.read(1000)
    writer.write(data.decode().upper().encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def run():
    loop = asyncio.get_running_loop()
    server = await asyncio.start_server(echo, host="0.0.0.0", port=6666, loop=loop)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run())
