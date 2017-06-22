# -*- coding: utf-8 -*-

import pickle
import numpy as np


def merge_dist(dist_a, dist_b):
    """
    Compute the merge of the distributions
    :param dist_a:
    :param dist_b:
    :return:
    """
    low_a, high_a, cnt_a, mean_a, squared_a = dist_a
    low_b, high_b, cnt_b, mean_b, squared_b = dist_b
    updated_mean = (cnt_a * mean_a + cnt_b * mean_b) / (cnt_a + cnt_b)
    updated_squared = (cnt_a * squared_a + cnt_b * squared_b) / (cnt_a + cnt_b)
    return low_a, high_b, cnt_a + cnt_b, updated_mean, updated_squared


def dist_sim(dist_a, dist_b, alpha=0.001):
    """
    Compute the similarity of two distributions
    :param dist_a:
    :param dist_b:
    :param alpha:
    :return:
    """
    low_a, high_a, cnt_a, mean_a, squared_a = dist_a
    low_b, high_b, cnt_b, mean_b, squared_b = dist_b
    updated_mean = (cnt_a * mean_a + cnt_b * mean_b) / (cnt_a + cnt_b)
    updated_squared = (cnt_a * squared_a + cnt_b * squared_b) / (cnt_a + cnt_b)
    deviation = np.sqrt(updated_squared - updated_mean ** 2)
    return np.sum(np.abs(mean_a - mean_b) / (deviation + alpha))


flow_model = pickle.load(open(r'C:\Users\apple\Desktop\流量分析\inside.tcpdump_week2_2\flow_model.pkl', 'rb'))

min_port = 0
max_port = 1024
merge_threshold = 100
merge_flow_model = dict()
for key, value in flow_model.items():
    if min_port <= key <= max_port:
        merge_flow_model[key] = list()
        for pkt_len, stats in value.items():
            merge_flow_model[key].append((pkt_len, pkt_len, stats[0], stats[1], stats[2]))
    else:
        continue

for key, stats_list in merge_flow_model.items():
    print(key)
    print(len(stats_list))
    while True:
        merge_cnt = 0
        merge_tag = 0
        while merge_tag < len(stats_list)-1:
            stats_a = stats_list[merge_tag]
            stats_b = stats_list[merge_tag+1]
            sim_score = dist_sim(stats_a, stats_b)
            if sim_score <= merge_threshold:
                merged_stats = merge_dist(stats_a, stats_b)
                stats_list.pop(merge_tag)
                stats_list.pop(merge_tag)
                stats_list.insert(merge_tag, merged_stats)
                merge_cnt += 1
            else:
                merge_tag += 1
        if merge_cnt == 0:
            break
