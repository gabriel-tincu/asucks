"""
    http://www.faqs.org/rfcs/rfc1928.html
"""
from asyncio.streams import StreamReader, StreamWriter
from dataclasses import dataclass
from threading import Event
from typing import Any, Optional, Set, Union

import aiohttp
import asyncio
import enum
import ipaddress
import json
import logging
import socket
import ssl
import struct

SOCKS5_VER = b"\x05"
RSV = b"\x00"
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
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
    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
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
