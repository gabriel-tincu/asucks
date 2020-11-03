# asyncio SOCKS5 server

This is still very much a work in progress but the aim goal is to

- Provide support for:
   1) [x] CONNECT
   2) [ ]  BIND
   3) [ ] UDP
- Provide support for:
   1) [X] no auth
   2) [X] user+pass auth
   3) [ ] some custom methods
- Add unit tests or maybe dockerised systests
- Add a dockerfile plus instructions

## Usage

```shell script
$ pip install asucks
$ python -m asucks.server --host 127.0.0.1 --port 1080
```

In another tab
```shell script
$ curl -x socks5h://127.0.0.1:1080 http://www.google.com/
```

## Why

I had issues with a golang implementation I found online and one thing led to another.
