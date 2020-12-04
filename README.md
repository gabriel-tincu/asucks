# Asyncio SOCKS5 Server


![Tests](https://github.com/gabriel-tincu/asucks/workflows/Test%20Suite/badge.svg)
![Style checks](https://github.com/gabriel-tincu/asucks/workflows/Lint/badge.svg)

This is still a work in progress but among the aim goals are:

- Provide support for:
   1) [x] CONNECT
   2) [ ] BIND
   3) [ ] UDP

- Add a dockerfile plus instructions

Currently there is a growing test suite that handles both unit and integration tests (those could use some improvement)

- Provides support for authentication methods:
   1) no auth
   2) user + password

## Usage

```shell script
$ pip install asucks
$ python -m asucks.server --host 127.0.0.1 --port 1080
```

In another tab
```shell script
$ curl -x socks5h://127.0.0.1:1080 http://www.google.com/
```

## CLI Options

```shell script
$ python -m asucks.server --help
Usage: server.py [OPTIONS]

Options:
  --port INTEGER      Server port
  --host TEXT         Network interface
  --username TEXT     Username for user/pass auth
  --password TEXT     Password for user/pass auth
  --log-level TEXT    Log level visible
  --use-sockets TEXT  Use the base socket server implementation
```

## Contributing

I'm using [Poetry](https://python-poetry.org) for dependency management. PR's are welcome
as well as feature requests
