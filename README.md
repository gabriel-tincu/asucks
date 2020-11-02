# asyncio SOCKS5 server

This is still very much a work in progress but the aim goal is to

- Provide support for at least 2 out of 3 commands (probably UDP and CONNECT)
- Provide support for no auth / user+pass auth and some custom methods
- Add unit tests or maybe dockerised systests 
- Add a dockerfile plus instructions

## Usage

```shell script
$ git clone https://github.com/gabriel-tincu/asucks
$ cd asucks
$ virtualenv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ python -m server --host 127.0.0.1 --port 1080
```


