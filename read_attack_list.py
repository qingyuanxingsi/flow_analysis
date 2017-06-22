# -*- coding: utf-8 -*-

import codecs
import pickle

local_file = codecs.open(r'attacks.txt', encoding='utf-8')

local_file.readline()
attack_list = list()
for line in local_file:
    pieces = line.strip().split(',')
    day = pieces[1]
    time = pieces[2]
    domain_ip = pieces[3]
    score = int(pieces[4])
    attack = pieces[5]
    attack_list.append((day, time, domain_ip, score, attack))

print(len(attack_list))

pickle.dump(attack_list, open(r'attack_list.pkl', 'wb'))



