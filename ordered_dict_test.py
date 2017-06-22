# -*- coding:utf-8 -*-

import collections

d = {2: 3, 1: 89, 4: 5, 3: 0}
od = collections.OrderedDict(sorted(d.items()))
print(od)
