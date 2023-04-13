import re


class _BinPair:
    def __init__(self, val, wild):
        self.val = val
        self.wild = wild

    @property
    def val(self):
        return self._val

    @val.setter
    def val(self, value):
        self._val = 1 if int(value) > 0 else 0

    @property
    def wild(self):
        return self._wild

    @wild.setter
    def wild(self, value):
        self._wild = 1 if int(value) > 0 else 0
        if self._wild == 1:
            self.val = 0

    def __eq__(self, other):
        # 仅当 wild 和 val 都相等时，该 pair 才是相等的
        return self.wild == other.wild and self.val == other.val

    def __contains__(self, item):
        # 如果 item 的 wild 为 1 则 self 必不包含 item
        if item.wild == 1:
            return False
        # 如果 self 的 wild 为 1 而 item 的 wild 为 0 则 self 必包含 item
        if self.wild == 1:
            return True
        # 如果 self 和 item 的 wild 都为 0， 那必然不会出现包含关系，只能是相等或不等
        return False

    def __str__(self):
        return f"{self.val}/{self.wild}"


_BINS = {
    "0/0": _BinPair(0, 0),
    "0/1": _BinPair(0, 1),
    "1/0": _BinPair(1, 0),
    "1/1": _BinPair(1, 1)
}


def _bin_pair(val, wild):
    return _BINS[f"{val}/{wild}"]


class _BaseOctetPair:
    def __init__(self, val: str, wild: str):
        val_rlt = re.search("[01]+", val.replace(" ", "").replace("_", ""))
        if not val_rlt:
            raise ValueError(f"{val} not a bin string.")
        wild_rlt = re.search("[01]+", wild.replace(" ", "").replace("_", ""))
        if not wild_rlt:
            raise ValueError(f"{wild} not a bin string.")
        self.bins = [_bin_pair(val, wild) for val, wild in zip(list(val_rlt.group()), list(wild_rlt.group()))]

    def __eq__(self, other):
        # 所有的 binPair 都相等，才能判断 self 与 other 相等
        return all([b1 == b2 for b1, b2 in zip(self.bins, other.bins)])

    def __contains__(self, item):
        # 如果 self 与 item 相等，则 self 必不包含 item， 必须先排除全部相等的情况
        if self == item:
            return False
        # 仅当 self 的每个 binPair 要么与 item 的每个 bin 相等(不能全等)，要么包含(最少一个)时，self 包含 bin 的关系才成立
        eq_relation = [b1 == b2 for b1, b2 in zip(self.bins, item.bins)]
        ctn_relation = [b2 in b1 for b1, b2 in zip(self.bins, item.bins)]
        return all([e or c for e, c in zip(eq_relation, ctn_relation)])

    def __str__(self):
        val = int(''.join(map(lambda b: str(b.val), self.bins)), 2)
        wild = int(''.join(map(lambda b: str(b.wild), self.bins)), 2)
        return f"{val}/{wild}"


class IPv4Pair(_BaseOctetPair):
    def __init__(self, ip: str, wild: str):
        self.sep = " "
        ip_in_bin = list(map(lambda part: bin(int(part, 10))[2:].zfill(8), ip.split(".")))
        wild_in_bin = list(map(lambda part: bin(int(part, 10))[2:].zfill(8), wild.split(".")))
        super(IPv4Pair, self).__init__(''.join(ip_in_bin), ''.join(wild_in_bin))

    def __str__(self):
        ip_parts = []
        wild_parts = []
        for i in range(4):
            ip_parts.append(str(int(''.join(map(lambda b: str(b.val), self.bins[8 * i: 8 * i + 8])), 2)))
            wild_parts.append(str(int(''.join(map(lambda b: str(b.wild), self.bins[8 * i: 8 * i + 8])), 2)))
        return f"{'.'.join(ip_parts)}{self.sep}{'.'.join(wild_parts)}"


def acl_ip(*, ip_prefix, wild=None, proto="ipv4"):
    if not wild:
        ip_prefix, wild = ip_prefix.split("/")
    if proto == "ipv4":
        return IPv4Pair(ip_prefix, wild)
    raise NotImplemented


if __name__ == '__main__':
    bo1 = _BaseOctetPair("01", "11")
    bo2 = _BaseOctetPair("00", "01")
    bo3 = _BaseOctetPair("10", "00")
    print(bo1, bo2)
    print(bo3 in bo1, bo3 in bo2)
    ip1 = IPv4Pair("192.169.1.100", "0.63.0.255")
    ip2 = IPv4Pair("192.168.1.65", "0.0.0.1")
    print(ip1)
    print(ip2)
    print(ip2 in ip1)
