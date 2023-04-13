import re
from collections import UserList

NAMED = {
    "www": 80,
    "http": 80,
    "https": 443,
}


# _PortType 为 _SinglePort 对象特异化 type，用于实现命名端口向数字端口的转换
class _PortType(type):
    def __call__(cls, port, *args, **kwargs):
        if isinstance(port, str) and not port.isdigit():
            try:
                port = NAMED[port]
            except KeyError:
                raise ValueError(f"{port} out of Known name port range.")
        if not 0 < int(port) < 65536:
            raise ValueError(f"{port} out of range 1-65535.")
        obj = super(_PortType, cls).__call__(port)
        return obj


# _SinglePort 封装一个单独的端口，大部分行为等同 int
class _SinglePort(int, metaclass=_PortType):
    __metaclass = _PortType

    def __contains__(self, item):
        # 单个接口的包含关系是不可能的
        return False


# _RangePort 封装一个端口的范围，当首位相等时，hash 值同一个 _SinglePort 对象
class _RangePort:
    def __init__(self, port):
        if isinstance(port, _SinglePort):
            self.range = [_SinglePort, _SinglePort]
            return
        if isinstance(port, str):
            self.range = [_SinglePort(p) for p in re.findall(r"\d+", port)]
            if len(self.range) == 2 and self.range[0] <= self.range[1] < 65536:
                return
        raise ValueError(f"illegal range: {port}")

    def is_single(self) -> bool:
        if self.range[0] == self.range[1]:
            return True

    def __contains__(self, item):
        # 相等必不包含
        if self.__eq__(item):
            return False
        # 不等是判断包含关系的前提
        if isinstance(item, _SinglePort):
            return self.range[0] <= item <= self.range[1]
        if isinstance(item, _RangePort):
            return self.range[0] <= item.range[0] and item.range[1] <= self.range[1]
        return NotImplemented

    def __eq__(self, other):
        # 针对与 _SinglePort 的相等比较，单侧实现，双向可用。
        if isinstance(other, _SinglePort):
            return self.range[0] == other == self.range[1]
        if isinstance(other, _RangePort):
            return self.range[0] == other.range[0] and self.range[1] == other.range[1]
        return NotImplemented

    def __and__(self, other):
        other = _RangePort(other) if isinstance(other, _SinglePort) else other
        if not isinstance(other, _RangePort):
            ValueError("type of other must be _RangePort.")
        # 对比收尾，
        first = max(self.range[0], other.range[0])
        last = min(self.range[1], other.range[1])
        return self._new(first, last)

    def __or__(self, other):
        other = _RangePort(other) if isinstance(other, _SinglePort) else other
        if not isinstance(other, _RangePort):
            ValueError("type of other must be _RangePort.")
        # 相交合并
        if self & other:
            first = min(self.range[0], other.range[0])
            last = max(self.range[1], other.range[1])
            return self._new(first, last)
        # 相邻合并
        if self.range[0] - other.range[1] == 1:
            return self._new(other.range[0], self.range[1])
        if other.range[0] - self.range[1] == 1:
            return self._new(self.range[0], other.range[1])
        # 其他情况，合并失败
        return None

    def __hash__(self):
        # 如果起始的接口相同，那等同于一个 _SinglePort 对象，那 Hash 应该也相等
        return hash(self.range[0]) if self.range[0] == self.range[1] else hash(f"{self.range[0] - self.range[1]}")

    def __str__(self):
        return f"{self.range[0]}" if self.range[0] == self.range[1] else f"{self.range[0]}-{self.range[1]}"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def _new(first, last):
        # first 端口和 last 端口必须满足关系，否则返回 None，意味着操作失败
        if last >= first:
            return _RangePort(f"{first}-{last}")
        return None


# ListPort 该 module 中暴露的类，可以解析合并比较 acl 中的端口范围
class _BasePort(UserList):
    def __init__(self, ports):
        self.names = {}
        self.sep = ", "
        super(_BasePort, self).__init__(self._prev(ports))
        self._merge()

    def append(self, ports):
        # 增加新值
        self.data.extend(self._prev(ports))
        self._merge()

    def pop(self, i=-1):
        ele = super(_BasePort, self).pop(i)
        self._merge()
        return ele

    # extend 方法与 append 相同
    extend = append
    insert = pop
    remove = None

    def __contains__(self, item):
        # 包含的前提是不等
        if self == item:
            return False
        if isinstance(item, _BasePort):
            return all(map(lambda p: self._single_contain(p), item))
        if isinstance(item, (_SinglePort, _RangePort)):
            return self._single_contain(item)
        return NotImplemented

    def _single_contain(self, single_item):
        return any(map(lambda x: self.port_factory(single_item) in x or self.port_factory(single_item) == x, self.data))

    def __eq__(self, other):
        if not isinstance(other, _BasePort):
            other = _BasePort(other)
        if len(other) != len(self):
            return False
        return all(map(lambda p1, p2: p1 == p2, self.data, other))

    def _prev(self, ports):
        if isinstance(ports, (_SinglePort, _RangePort, int)):
            ports = str(ports)
        if isinstance(ports, str):
            ports = ports.strip()
            if ", " in ports:
                self.sep = ", "
            elif " ," in ports:
                self.sep = " ,"
            elif "," in ports:
                self.sep = ","
            elif " " in ports:
                self.sep = " "
            ports = re.split(f"\s*{self.sep}\s*", ports.strip())
        return [self.port_factory(p) for p in ports]

    def _merge(self):
        after_merge = []
        for val in sorted(self.data, key=lambda p: p.range[0]):
            if not after_merge:
                after_merge.append(val)
                continue
            # 可以证明只要和最后一个值合并即可
            one_shot = after_merge[-1] | val
            if one_shot:
                after_merge[-1] = one_shot
            else:
                after_merge.append(val)
        self.data = after_merge

    # _port_factory 根据传入的 port 信息, 输出 _RangePort 对象，不直接输出 _SinglePort 对象，降低复杂度
    def port_factory(self, port):
        port = str(port).strip()
        # 如果是字母组成的端口，考虑知名端口
        if re.match(r"[a-zA-Z-]+", port):
            p = str(_SinglePort(port))
            self.names[p] = port
            print(self.names)
            return _RangePort(f"{p}-{p}")
        # 如果不是，那就是数字组成的端口或端口范围 (不考虑知名端口组成的范围)
        ports = re.findall(r"\d+", port)
        if len(ports) == 1:
            return _RangePort(f"{ports[0]}-{ports[0]}")
        if len(ports) == 2:
            return _RangePort(f"{ports[0]}-{ports[1]}")
        raise ValueError(f"illegal port description: {port}")

    def __str__(self):
        return self.sep.join(map(self._str_port, self.data))

    def _str_port(self, rd: _RangePort):
        return self.names.get(str(rd)) if rd.is_single() and self.names.get(str(rd)) else str(rd)


class HuaweiPort(_BasePort):

    def __str__(self):
        if len(self.data) == 0:
            return ""
        if len(self.data) == 1:
            rd = self.data[0]
            if rd.is_single():
                return f"eq {self._str_port(rd)}"
        return f"range {super(HuaweiPort, self).__str__()}"


def acl_port(port_descr, vendor="Huawei"):
    if vendor == "Huawei":
        return HuaweiPort(port_descr)
    raise NotImplemented


if __name__ == '__main__':
    # myl = _BasePort([1, 2, 3, 4, "www", "100"])
    # ly2 = _BasePort("100,1-4")
    # print(ly2, myl)
    # print(ly2 in myl, myl in ly2, myl == ly2)
    # ly2.append("80,https")
    # print(ly2, myl)
    # print(ly2 in myl, myl in ly2, myl == ly2)
    # myl.append('98-400, 700-1000')
    # print(ly2)
    # print(ly2 in myl, myl in ly2, myl == ly2)
    print(acl_port("1-65535"))
