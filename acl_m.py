import ipaddress
import time

from textfsm import TextFSM
from pprint import pprint


def parse_acl(acl):

    with open('dis_acl.testfsm',mode='r',encoding='utf-8') as t:

        template = TextFSM(t)
        datas = template.ParseTextToDicts(acl)
        return datas

class ACLMatcher:
    def __init__(self, mask, address):
        self.mask = mask
        self.address = address

    def wildcard_mask_test(self, test_octet, acl_octet, acl_wildcard_octet):

        test_result = test_octet | acl_wildcard_octet
        acl_result = acl_octet | acl_wildcard_octet
        return (acl_result == test_result)

    def test_octet(self, acl_octet, acl_wildcard_octet):
        matches = []
        if acl_wildcard_octet == 0:
            matches.append(acl_octet)
            return matches
        else:
            for test_octet in range(0, 256):
                if self.wildcard_mask_test(test_octet, acl_octet, acl_wildcard_octet):
                    matches.append(test_octet)
            return matches

    def list_of_matches_acl(self):
        if self.address == '':
            return ''

        if self.mask == '0':
            ip = []
            ip.append(ipaddress.IPv4Address(self.address))
            result = list(ipaddress.collapse_addresses(ip))
            return result
        potential_matches = []
        acl_address_octets = self.address.split('.')
        for n in range(0, 4):
            acl_address_octets[n] = int(acl_address_octets[n])

        acl_mask_octets = self.mask.split('.')
        for n in range(0, 4):
            acl_mask_octets[n] = int(acl_mask_octets[n])

        matches_octet_1_ref = self.test_octet(acl_address_octets[0], acl_mask_octets[0])
        matches_octet_2_ref = self.test_octet(acl_address_octets[1], acl_mask_octets[1])
        matches_octet_3_ref = self.test_octet(acl_address_octets[2], acl_mask_octets[2])
        matches_octet_4_ref = self.test_octet(acl_address_octets[3], acl_mask_octets[3])


        for n1 in matches_octet_1_ref:
            for n2 in matches_octet_2_ref:
                for n3 in matches_octet_3_ref:
                    for n4 in matches_octet_4_ref:
                        potential_matches.append(str(n1) + '.' + str(n2) + '.' + str(n3) + '.' + str(n4))
        ip = []
        for m in potential_matches:
            ip.append(ipaddress.ip_address(m))
        result = list(ipaddress.collapse_addresses(ip))
        return result

def determine_acl_type(acl_rule):
    sip = acl_rule["SourceIP"]
    dip = acl_rule["DestinationIP"]
    sp = acl_rule["SourcePort"]
    dp = acl_rule["DestinationPort"]

    if sip and dip and sp and dp:
        return "A"
    elif sip and dip and sp:
        return "B"
    elif sip and dip and dp:
        return "C"
    elif sip and dip:
        return "D"
    elif sip and sp and dp:
        return "E"
    elif sip and sp:
        return "F"
    elif sip and dp:
        return "G"
    elif dip and sp and dp:
        return "H"
    elif dip and dp:
        return "I"
    elif dip and sp:
        return "J"
    elif sip:
        return 'K'
    elif dip:
        return 'L'
    else:
        return "M"


def if_rule_contain(add_rule, rule_list):

    # 判断元素包含的规则
    def check_contain_rule(contain_rule):
        contain_rule_type = determine_acl_type(contain_rule)
        # 如果新增规则中包含端口，将先判断端口
        add_src_port = add_rule['SourcePort']
        add_dst_port = add_rule['DestinationPort']
        if (add_src_port and add_src_port != contain_rule['SourcePort']) \
                or (add_dst_port and add_dst_port != contain_rule['DestinationPort']):
            return False

        if add_rule['SourceIP'] and add_rule['DestinationIP']:
            add_src_ip = ACLMatcher(add_rule['SourceWildcard'], add_rule['SourceIP']).list_of_matches_acl()
            add_dst_ip = ACLMatcher(add_rule['DestinationWildcard'], add_rule['DestinationIP']).list_of_matches_acl()
            old_src_ip = ACLMatcher(contain_rule['SourceWildcard'], contain_rule['SourceIP']).list_of_matches_acl()
            old_dst_ip = ACLMatcher(contain_rule['DestinationWildcard'],
                                    contain_rule['DestinationIP']).list_of_matches_acl()
            src_new_contain_old = any(old_ip.subnet_of(add_ip) for add_ip in add_src_ip for old_ip in old_src_ip)
            src_old_contain_new = any(add_ip.subnet_of(old_ip) for add_ip in add_src_ip for old_ip in
                                      old_src_ip) if add_rule_type == contain_rule_type else False
            dst_new_contain_old = any(old_ip.subnet_of(add_ip) for add_ip in add_dst_ip for old_ip in old_dst_ip)
            dst_old_contain_new = any(add_ip.subnet_of(old_ip) for add_ip in add_dst_ip for old_ip in
                                      old_dst_ip) if add_rule_type == contain_rule_type else False
            if (add_src_ip == old_src_ip) and (add_dst_ip == old_dst_ip):
                return 0
            elif ((add_src_ip == old_src_ip) and dst_new_contain_old) or (
                    (add_dst_ip == old_dst_ip) and src_new_contain_old):
                return 1
            elif ((add_src_ip == old_src_ip) and dst_old_contain_new) or (
                    (add_dst_ip == old_dst_ip) and src_old_contain_new):
                return 2
            elif (src_new_contain_old and dst_old_contain_new) or (src_old_contain_new and dst_new_contain_old):
                return False
            elif src_new_contain_old and dst_new_contain_old:
                return 1
            elif src_old_contain_new and dst_old_contain_new:
                return 2
        else:
            mask_key = 'SourceWildcard' if add_rule['SourceWildcard'] else 'DestinationWildcard'
            address_key = 'SourceIP' if add_rule['SourceIP'] else 'DestinationIP'
            add_rule_ip = ACLMatcher(add_rule[mask_key], add_rule[address_key]).list_of_matches_acl()
            old_rule_ip = ACLMatcher(contain_rule[mask_key], contain_rule[address_key]).list_of_matches_acl()
            new_contain_old = any(old_ip.subnet_of(add_ip) for add_ip in add_rule_ip for old_ip in old_rule_ip)
            old_contain_new = any(add_ip.subnet_of(old_ip) for add_ip in add_rule_ip for old_ip in
                                  old_rule_ip) if add_rule_type == contain_rule_type else False
            if add_rule_ip == old_rule_ip and add_rule_type == contain_rule_type:
                return 0
            elif new_contain_old:
                return 1
            elif old_contain_new:
                return 2

    def check_contained_rule(contained_rule):
        ...

    add_rule_id = 0

    # 判断规则协议，分为IP和非IP
    if add_rule['Protocol'] == 'ip':
        # 判断新增规则类型，定义元素包含和被包含映射表
        add_rule_type = determine_acl_type(add_rule)
        rule_list_contain = [i for i in rule_list if determine_acl_type(i) in rule_check_map[add_rule_type]['contain']]
        rule_list_contained = [i for i in rule_list if determine_acl_type(i) in rule_check_map[add_rule_type]['contained']]

        # 遍历元素包含列表
        for contain_rule in rule_list_contain:
            check_result = check_contain_rule(contain_rule)
            if check_result == 0 and contain_rule['Protocol'] == 'ip':
                print(f'新增规则和原有规则冲突,{contain_rule}')
            elif check_result == 0:
                if add_rule['Action'] == contain_rule['Action']:
                    print(f'新增规则包含原有规则，可以和{contain_rule}合并')
                else:
                    add_rule_id = int(contain_rule['RuleID']) + 1
            elif check_result == 1 :
                if add_rule['Action'] == contain_rule['Action']:
                    print(f'新增规则包含原有规则，可以和{contain_rule}合并')
                else:
                    add_rule_id = int(contain_rule['RuleID']) + 1
            elif check_result == 2 and contain_rule['Protocol'] == 'ip':
                if add_rule['Action'] == contain_rule['Action']:
                    print(f'新增规则已被原有规则包含,{contain_rule}')
                else:
                    add_rule_id = int(contain_rule['RuleID']) - 1
            elif check_result == 2:
                if add_rule['Action'] == contain_rule['Action']:
                    add_rule_id = int(contain_rule['RuleID']) + 1
                else:
                    add_rule_id = int(contain_rule['RuleID']) - 1

        # 遍历元素被包含列表
        for contained_rule in rule_list_contained:
            mask_key = 'SourceWildcard' if contained_rule['SourceWildcard'] else 'DestinationWildcard'
            address_key = 'SourceIP' if contained_rule['SourceIP'] else 'DestinationIP'
        return add_rule_id
    else:
        pass


if __name__ == '__main__':
    start_time = time.time()
    rule_check_map = {
        'A': {'contain': ['A'], 'contained': ['B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J','K','L']},
        'B': {'contain': ['A', 'B'], 'contained': ['D','F','J','K','L']},
        'C': {'contain': ['A','C'], 'contained': ['D','G','I','K','L']},
        'D': {'contain': ['A','B','C','D'], 'contained': ['K', 'L']},
        'E': {'contain': ['A', 'E'], 'contained': ['F','G','K']},
        'F': {'contain': ['A','B','E','F'], 'contained': ['K']},
        'G': {'contain': ['A','C','E','G'], 'contained': ['K']},
        'H': {'contain': ['A', 'H'], 'contained': ['I','J','L']},
        'I': {'contain': ['A','C','H','I'], 'contained': ['L']},
        'J': {'contain': ['A', 'B', 'H','J'], 'contained': ['L']},
        'K': {'contain': ['A','B','C','D','E','F','G','K'], 'contained': []},
        'L': {'contain': ['A','B','C','D','H','I','J','L'], 'contained': []},
        'M': {'contain': [], 'contained': []},
    }

    # ruleid = input('规则ID:')
    # action = input('执行动作:')
    # proto = input('协议:')
    # sip = input('源地址:')
    # swd = input('源地址通配符:')
    # dip = input('目标地址:')
    # dwd = input('目标地址通配符')
    # sp = input('源端口:')
    # dp = input('目标端口:')

    ruleid = '11'
    action = 'deny'
    proto = 'ip'
    sip = '192.168.1.1'
    swd = '0.0.0.0'
    dip = ''
    dwd = ''
    sp = ''
    dp = ''

    add_rule = {
        'Action': action,
        'DestinationIP': dip,
        'DestinationPort': dp,
        'DestinationWildcard': dwd,
        'Protocol': proto,
        'RuleID': ruleid,
        'SourceIP': sip,
        'SourcePort': sp,
        'SourceWildcard': swd
    }
    add_rule_type = determine_acl_type(add_rule)
    with open('acl.txt',mode='r',encoding='utf-8') as f:
        acl = f.read()
        rule_list = parse_acl(acl)

    result = if_rule_contain(add_rule,rule_list)
    print(f'建议从RuleID：{result}后插入规则')
    end_time = time.time() - start_time
    print(end_time)