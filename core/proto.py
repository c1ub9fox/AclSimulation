
SUPPORT_PROTO = ["ip", "icmp", "udp", "tcp"]


class _Protocol:
    def __init__(self, name):
        if name not in SUPPORT_PROTO:
            raise ValueError(f"unspport protocol {name}。")
        self.data = name

    def __eq__(self, other):
        if isinstance(other, _Protocol):
            return self.data == other.data
        raise NotImplemented

    def __contains__(self, item):
        if self == item:
            return False
        if isinstance(item, _Protocol):
            if self.data == "ip":
                return True
            else:
                return False
        raise NotImplemented

    def __str__(self):
        return self.data


PROTO_OBJ = {
    "ip": _Protocol("ip"),
    "icmp": _Protocol("icmp"),
    "udp": _Protocol("udp"),
    "tcp": _Protocol("tcp"),
}


def acl_proto(name):
    return PROTO_OBJ[name]


if __name__ == '__main__':
    icmp = acl_proto("icmp")
    ip = acl_proto("ip")
    udp = acl_proto("udp")
    tcp = acl_proto("tcp")

    print(tcp in ip)
    print(icmp in ip)

