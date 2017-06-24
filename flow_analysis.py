# -*- coding: utf-8 -*-

from scapy.all import *


# 0.6 0.5638528138528138

sim_threshold = 0.6
sig_dict = dict()


def longest_common_substring(s1, s2):
    m = [[0] * (1 + len(s2)) for i in range(1 + len(s1))]
    longest, x_longest = 0, 0
    for x in range(1, 1 + len(s1)):
        for y in range(1, 1 + len(s2)):
            if s1[x - 1] == s2[y - 1]:
                m[x][y] = m[x - 1][y - 1] + 1
                if m[x][y] > longest:
                    longest = m[x][y]
                    x_longest = x
            else:
                m[x][y] = 0
    score = 2 * longest / (len(s1) + len(s2))
    return s1[x_longest - longest: x_longest], score


local_files = [r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\1.pcap',
               r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\2.pcap',
               r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\3.pcap',
               r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\4.pcap',
               r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\5.pcap'
               ]

test_files = [r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\6.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\7.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\8.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\9.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\10.pcap']

flow_model = dict()
for local_file in local_files:
    reader = PcapReader(local_file)
    count = -1
    while count != 0:
        pkt = reader.read_packet()
        if pkt is None:
            break
        else:
            if 'Raw' in pkt:
                raw = pkt['Raw']
                payload = raw.load
                assert 'IP' in pkt
                ip = pkt['IP']
                dport = ''
                if 'TCP' in pkt:
                    tcp = pkt['TCP']
                    dport = tcp.dport
                elif 'UDP' in pkt:
                    udp = pkt['UDP']
                    dport = udp.dport
                else:
                    continue
                if dport not in flow_model:
                    flow_model[dport] = list()
                flow_model[dport].append(payload)
            else:
                continue
    reader.close()

for key, payloads in flow_model.items():
    sig_set = set()
    for index in range(0, len(payloads) - 1):
        payload_a = payloads[index]
        payload_b = payloads[index + 1]
        sig, score = longest_common_substring(payload_a, payload_b)
        if score > sim_threshold:
            sig_set.add(sig)
    sig_dict[key] = list(sig_set)

# pickle.dump(sig_dict, open(r'sig_dict.pkl', 'wb'))

# alert any any any -> any any (content:""; msg: "mountd access"; sid:1000000)
rule_file = open(r'rule.rules', 'w')
sid_start = 1000000
msg = 'Anomalous'
for key, sig_list in sig_dict.items():
    for sig in sig_list:
        sig_list = []
        for s in sig:
            hex_s = hex(s)[2:]
            if len(hex_s) == 1:
                hex_s += '0'
            sig_list.append(hex_s)
        sig_str = '|'+''.join(sig_list)+'|'
        tcp_rule = 'alert %s any any -> any %d (content:\"%s\"; msg: \"%s\"; sid:%d)\n' % ('tcp', key, sig_str, msg, sid_start)
        sid_start += 1
        udp_rule = 'alert %s any any -> any %d (content:\"%s\"; msg: \"%s\"; sid:%d)\n' % ('udp', key, sig_str, msg, sid_start)
        sid_start += 1
        rule_file.writelines(tcp_rule)
        rule_file.writelines(udp_rule)
rule_file.flush()
rule_file.close()

records = list()
for test_file in test_files:
    reader = PcapReader(test_file)
    count = -1
    raw_cnt = 0
    match_cnt = 0
    while count != 0:
        pkt = reader.read_packet()
        if pkt is None:
            break
        else:
            if 'Raw' in pkt:
                dport = ''
                if 'TCP' in pkt:
                    tcp = pkt['TCP']
                    dport = tcp.dport
                elif 'UDP' in pkt:
                    udp = pkt['UDP']
                    dport = udp.dport
                else:
                    continue
                raw_cnt += 1
                if dport not in sig_dict:
                    continue
                else:
                    raw = pkt['Raw']
                    payload = raw.load
                    assert 'IP' in pkt
                    ip = pkt['IP']
                    matched = False
                    sig_list = sig_dict[dport]
                    for sig in sig_list:
                        if sig in payload:
                            matched = True
                            break
                    if matched:
                        match_cnt += 1
            else:
                continue
    reader.close()

    match_score = match_cnt / raw_cnt
    records.append((match_cnt, raw_cnt, match_score))

sum = 0.0
for match, raw, score in records:
    sum += score
avg_score = sum / len(records)
print(avg_score)
