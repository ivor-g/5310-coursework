import struct

def encode_name(name: str) -> bytes:
    """Encode an uncompressed QNAME. Provided as a starting point."""
    labels = name.rstrip(".").split('.')
    serialisation = bytearray()

    for label in labels:
        raw = label.encode("ascii")
        length = len(raw)
        serialisation.append(length)
        serialisation += raw

    serialisation.append(0)

    return bytes(serialisation)

def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """

    name = packet[offset:]
    length = int(name[0]) + 1
    labels = []

    while length - 1 != 0:
        label = name[1:length].decode("ascii")
        labels.append(label)
        name = name[length:]
        offset += length
        length = int(name[0]) + 1

    domain = ".".join(labels)

    return domain, offset + 1

serialised = encode_name("this.is.a.string")
print(serialised)
domain, offset = decode_name(serialised, 0)
print(domain, offset)

packed = struct.pack(">bhl", 1, 2, 3)
unpacked = struct.unpack('>bhl', packed)
print(f"packed type: {type(packed)}")
print(f"packed: {packed}")
print(f"unpacked type: {type(unpacked)}")
print(f"unpacked: {unpacked}")

