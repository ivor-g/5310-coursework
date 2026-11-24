
def encode_name(name: str) -> bytes:
    """Encode an uncompressed QNAME. Provided as a starting point."""
    labels = name.split('.')
    serialisation = ""

    for label in labels:
        serialisation += str(len(label)) + label

    serialisation += "0"

    return serialisation.encode("utf-8")


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """

    name = packet[offset:]
    name = name.decode("utf-8")
    length = int(name[0]) + 1
    labels= []

    while length - 1 != 0:
        labels.append(name[1:length])
        name = name[length:]
        offset += length
        length = int(name[0]) + 1

    domain = ".".join(labels)

    return domain, offset + 1

serialised = encode_name("this.is.a.string")
print(serialised)
domain, offset = decode_name(serialised, 0)
print(domain, offset)
