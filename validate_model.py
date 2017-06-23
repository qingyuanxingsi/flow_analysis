# -*- coding: utf-8 -*-

import pickle
from scapy.all import *

test_files = [r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\7.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\8.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\9.pcap',
              r'C:\Users\apple\Desktop\流量分析\ms12-020漏洞攻击流量\10.pcap']

sig_dict = pickle.load(open(r'sig_dict.pkl', 'rb'))

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

    match_score = match_cnt/raw_cnt
    records.append((match_cnt, raw_cnt, match_score))

sum = 0.0
for match, raw, score in records:
    sum += score
avg_score = sum/len(records)
print(avg_score)

