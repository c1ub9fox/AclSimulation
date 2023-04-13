from core.ipPair import acl_ip
from core.port import acl_port
from core.proto import acl_proto


class _BasicRule:

    def __init__(self, seq, action, protocol, src_ip, src_port, dst_ip, dst_port):
        self.seq = seq
        self.action = action
        self.protocol = acl_proto(protocol)
        self.src_ip = acl_ip(ip_prefix=src_ip)
        self.src_port = acl_port(src_port)
        self.dst_ip = acl_ip(ip_prefix=dst_ip)
        self.dst_port = acl_port(dst_port)

    def __str__(self):
        return f"rule {self.seq} {self.action} {self.protocol} source {self.src_ip} source-port {self.src_port} destination {self.dst_ip} destination-port {self.dst_port}"


if __name__ == '__main__':
    a = _BasicRule(seq=10, action="permit", protocol="tcp", src_ip="192.168.0.1/0.1.255.255", src_port="1000-65535", dst_ip="10.195.100.0/0.0.63.255", dst_port="https")
    print(a)