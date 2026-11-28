#!/usr/bin/env python3
"""Student starter code: implement an iterative DNS resolver."""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys

from dns_model import DNSMessage, DNSQuestion, DNSRecord

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}
IN = 1


class DNSError(RuntimeError):
    pass


def fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def encode_name(name: str) -> bytes:
    """Encode an uncompressed QNAME. Provided as a starting point."""
    labels = name.rstrip(".").split('.')
    serialisation = bytearray()

    for label in labels:
        raw = label.encode("ascii")
        length = len(raw)

        if length > 63:
            raise DNSError(f"label too long: {label}")

        serialisation.append(length)
        serialisation += raw

    serialisation.append(0)

    return bytes(serialisation)

def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """
    name = packet[offset:]

    if not name:
        raise DNSError("offset reached end of packet")

    if name[0] >> 6 == 0x3:
        return resolve_name_compression(packet, offset), offset + 2

    length = int(name[0]) + 1
    labels = []

    while length - 1 != 0:
        if name[0] >> 6 == 0x3:
            name = resolve_name_compression(packet, offset)
            labels.append(name[:-1]) # get rid of extra . at end of name
            offset += 1
            break
        label = name[1:length].decode("ascii")
        labels.append(label)
        name = name[length:]
        offset += length
        length = int(name[0]) + 1

    domain = ".".join(labels)
    domain += "."

    return domain, offset + 1

def resolve_name_compression(packet: bytes, offset: int) -> str:
    name = packet[offset:]
    pointer = int.from_bytes(name[:2])&0x3fff

    if pointer >= offset:
        raise DNSError("Pointer is pointing to same address or larger")
    
    name, _ = decode_name(packet, pointer)
    return name

def make_query(msg: DNSMessage) -> bytes:
    """Build a standard UDP DNS query with recursion disabled."""
    header = struct.pack("!HHHHHH", msg.ident & 0xFFFF, msg.flags & 0xFFFF,
                         len(msg.questions), 0, 0, 0)
    body = b""
    for question in msg.questions:
        qname = encode_name(question.name)
        body += qname + struct.pack("!HH", question.type, question.cls)
    return header + body


def query_server(msg: DNSMessage, timeout: float, server: str) -> bytes:
    """Send one UDP query to SERVER and return the raw response bytes."""
    data = make_query(msg)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(data, (server, 53))
        response, _ = sock.recvfrom(4096)
    return response


def query(server: str, name: str, qtype: int, timeout: float, ident: int = -1) -> DNSMessage:
    """Send ONE query for NAME and QTYPE to SERVER and return the parsed reply.

    Recursion desired is off. If IDENT is -1 a random identifier is used.
    """
    if ident == -1:
        ident = random.randrange(0, 65536)
    msg = DNSMessage(ident=ident, flags=0, questions=[
                     DNSQuestion(fqdn(name), qtype)])

    response = query_server(msg, timeout, server)
    reply = parse_response(response, msg.ident)
    if reply.ident != msg.ident:
        raise DNSError("unexpected DNS response ID")
    return reply


def parse_response(packet: bytes, expected_id: int) -> DNSMessage:
    """TODO: parse header, question, and all resource-record sections.

    Your parser must support compressed names (RFC 1035 section 4.1.4) in
    owner names and NS, CNAME, and MX RDATA. Return a useful representation
    containing answer, authority, and additional records. Use the supplied
    DNSMessage, DNSQuestion, and DNSRecord classes from dns_model.py.
    """
    header = packet[:12]

    response_id, flags, QDCount, ANCount, NSCount, ARCount = struct.unpack("!HHHHHH", header)

    if response_id != expected_id:
        raise DNSError("Expected ID did not match response ID")

    questions = []
    offset = 12


    for i in range(QDCount):
        name, offset = decode_name(packet, offset)
        QType, QClass = struct.unpack("!HH", packet[offset : offset + 4])
        question = DNSQuestion(name, QType, QClass)
        questions.append(question)
        offset += 4

    answers, offset = get_records(packet, ANCount, offset)
    authorities, offset = get_records(packet, NSCount, offset)
    additionals, offset = get_records(packet, ARCount, offset)

    msg = DNSMessage(response_id, flags, questions, answers, authorities, additionals)

    return msg

def get_records(packet: bytes, count: int, offset: int) -> tuple[list, int]:
    items = []

    for i in range(count):
        name, offset = decode_name(packet, offset)
        AType, AClass, ttl, RDLength = struct.unpack("!HHLH", packet[offset : offset + 10])
        offset += 10
        data = packet[offset : offset + RDLength]

        if AType == QTYPE["NS"] or AType == QTYPE["CNAME"]:
            RData, _ = decode_name(packet, offset)
        elif AType == QTYPE["A"]:
            RData = socket.inet_ntoa(data)
        elif AType == QTYPE["MX"]:
            priority = data[:2] 
            server, _ = decode_name(packet, offset + 2)
            RData = priority, server
        else:
            RData = str(data)

        item = DNSRecord(name, AType, RData, AClass, ttl)
        items.append(item)
        offset += + RDLength

    return items, offset

def resolve_iteratively(name: str, qtype: int, root: str, timeout: float = 2.0,
                        trace: bool = False) -> list[DNSRecord]:
    """TODO: resolve NAME iteratively, starting at the ROOT server.

    Follow referrals using glue A records. Handle timeouts and NXDOMAIN/NODATA responses. Return the list of final answer DNSRecord objects.
    With TRACE, print each query and referral step.
    """
    raise NotImplementedError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("type", choices=QTYPE)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--server", metavar="ADDRESS",
                        help="send one query to this server")
    target.add_argument("--root", metavar="ADDRESS",
                        help="resolve iteratively, starting at this root server")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--trace", action="store_true",
                        help="print each resolution step (only with --root)")
    args = parser.parse_args()

    try:
        if args.server:
            response = query(args.server, args.name,
                             QTYPE[args.type], args.timeout)
            print(str(response))
        else:
            records = resolve_iteratively(
                args.name, QTYPE[args.type], args.root, args.timeout, args.trace)
            answer = DNSMessage(0, 0x8000, [DNSQuestion(fqdn(args.name), QTYPE[args.type])],
                                answers=records)
            print(str(answer))

    except DNSError as e:
        print(f"DNS error: {e}")
        return 1
    except socket.timeout:
        print("Query timed out")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
