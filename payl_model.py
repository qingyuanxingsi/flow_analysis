# -*- coding: utf-8 -*-

from scapy.all import *
import numpy as np
import collections
import pickle


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


def sample_md_distance(dist_a, new_sample, alpha=0.001):
    """
    Compute the Mahalanobis distance between distribution a and new sample
    :param dist_a:
    :param new_sample:
    :param alpha:
    :return:
    """
    low_a, high_a, cnt_a, mean_a, squared_a = dist_a
    deviation = np.sqrt(squared_a - mean_a ** 2)
    return np.sum(np.abs(mean_a - new_sample) / (deviation + alpha))


def gen_dist(pkt_bytes):
    """
    Generate per packet bytes
    :param pkt_bytes:
    :return:
    """
    payload_len = len(pkt_bytes)
    dist_result = np.zeros(pkt_size)
    for pkt_byte in pkt_bytes:
        dist_result[pkt_byte] += 1
    dist_result /= payload_len
    return dist_result


flow_model = dict()
pkt_size = 256


class FlowModel:
    def __init__(self, train_file):
        self.flow_model = dict()
        self.merged_flow_model = dict()
        self.train_file = train_file
        self.min_port = 0
        self.max_port = 1024
        self.merge_threshold = 100
        self.anomalous_threshold = 100

    def merge_flow(self, port, payload_len, cur_dist):
        """
        Update current mean and standard deviation stats
        :param port:
        :param payload_len:
        :param cur_dist:
        :return:
        """
        cnt, mean, squared = self.flow_model[port][payload_len]
        cnt += 1
        updated_mean = mean + (cur_dist - mean) / cnt
        updated_squared = squared + (cur_dist ** 2 - squared) / cnt
        # update flow model
        self.flow_model[port][payload_len] = (cnt, updated_mean, updated_squared)

    def validate_flow(self, port, payload):
        """
        Validate whether the flow is anomalous
        if anomalous, return True
        else return False
        :param port:
        :param payload:
        :return:
        """
        payload_len = len(payload)
        stats_list = self.merged_flow_model[port]
        cmp_tag = -1
        for stat_index, stat in enumerate(stats_list):
            low, high, cnt, mean, squared = stat
            if low <= payload_len <= high:
                cmp_tag = stat_index
                break
        if cmp_tag == -1:
            cmp_tag = len(stats_list) - 1
        new_sample = gen_dist(payload)
        sim_score = sample_md_distance(stats_list[cmp_tag], new_sample)
        if sim_score > self.anomalous_threshold:
            return True
        else:
            return False

    def merge_flow_model(self):
        """
        Merge flow model using clustering
        :return:
        """
        for key, value in self.flow_model.items():
            if self.min_port <= key <= self.max_port:
                self.merge_flow_model[key] = list()
                iter_cnt = 0
                for pkt_len, stats in value.items():
                    if iter_cnt == 0:
                        self.merge_flow_model[key].append((0, pkt_len, stats[0], stats[1], stats[2]))
                    else:
                        self.merge_flow_model[key].append((pkt_len, pkt_len, stats[0], stats[1], stats[2]))
                    iter_cnt += 1
            else:
                continue

        for key, stats_list in self.merge_flow_model.items():
            while True:
                merge_cnt = 0
                merge_tag = 0
                while merge_tag < len(stats_list) - 1:
                    stats_a = stats_list[merge_tag]
                    stats_b = stats_list[merge_tag + 1]
                    sim_score = dist_sim(stats_a, stats_b)
                    if sim_score <= self.merge_threshold:
                        merged_stats = merge_dist(stats_a, stats_b)
                        stats_list.pop(merge_tag)
                        stats_list.pop(merge_tag)
                        stats_list.insert(merge_tag, merged_stats)
                        merge_cnt += 1
                    else:
                        merge_tag += 1
                if merge_cnt == 0:
                    break

    def parse_flow(self):
        reader = PcapReader(self.train_file)
        count = -1
        process_tag = 0
        process_batch = 100000
        while count != 0:
            data = reader.read_packet()
            if data is None:
                break
            else:
                process_tag += 1
                if process_tag % process_batch == 0:
                    print('Processed %d batch(%d)...' % (int(process_tag / process_batch), process_batch))
                if 'TCP' in data:
                    unix_time = data.time
                    local_time = time.localtime(unix_time)
                    pkt_time = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
                    tcp = data['TCP']
                    dst_port = tcp.dport
                    pkt_bytes = bytes(data.payload.payload.payload)
                    payload_len = len(pkt_bytes)
                    cur_dist = gen_dist(pkt_bytes)
                    if dst_port not in self.flow_model:
                        self.flow_model[dst_port] = dict()
                    if payload_len not in self.flow_model[dst_port]:
                        self.flow_model[dst_port][payload_len] = (0, np.zeros(pkt_size), np.zeros(pkt_size))
                    self.merge_flow(dst_port, payload_len, cur_dist)
        reader.close()
        # Sort dictionary
        print('Sorting dict...')
        for key, value in self.flow_model.items():
            self.flow_model[key] = collections.OrderedDict(sorted(value.items()))
        print('Dumping model...')
        self.merge_flow_model()
        pickle.dump(self.merged_flow_model,
                    open(r'C:\Users\apple\Desktop\流量分析\inside.tcpdump_week2_2\merged_flow_model.pkl', 'wb'))


if __name__ == '__main__':
    local_file = r'C:\Users\apple\Desktop\流量分析\inside.tcpdump_week2_2\inside.tcpdump'
    flow_model = FlowModel(train_file=local_file)
    flow_model.parse_flow()
