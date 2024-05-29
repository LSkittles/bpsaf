# 对两份VEX IR日志进行对比

import re

def compareVEX(log_angr_flattened_path, log_rebuild_flattened_path):
    dict_angr = {}
    dict_rebuild = {}
    with open(log_angr_flattened_path, 'r') as log_angr:
        lines = log_angr.readlines()
        addr = ''
        for line in lines:
            # IRSB { 或 }
            if line == 'IRSB {\n' or line == '}\n' or line == '}':
                continue
            # IMark语句
            ind = line.find('IMark')
            if ind != -1:
                addr = re.findall(pattern=r'0x[0-9A-Fa-f]+', string=line)[0]
                # 未有对应列表则初始化
                if addr not in dict_angr:
                    dict_angr[addr] = []
                continue
            # 其余语句
            # 删除换行符后添加进dict
            dict_angr[addr].append(line.rstrip("\n"))
    with open(log_rebuild_flattened_path, 'r') as log_rebuild:
        lines = log_rebuild.readlines()
        addr = ''
        for line in lines:
            # IRSB { 或 }
            if line == 'IRSB {\n' or line == '}\n' or line == '}':
                continue
            # IMark语句
            ind = line.find('IMark')
            if ind != -1:
                addr = re.findall(pattern=r'0x[0-9A-Fa-f]+', string=line)[0]
                # 未有对应列表则初始化
                if addr not in dict_rebuild:
                    dict_rebuild[addr] = []
                continue
            # 其余语句
            dict_rebuild[addr].append(line.rstrip("\n"))
    
    order_hit = 0
    order_miss = 0
    for addr, lines in dict_rebuild.items():
        angr_lines = dict_angr[addr]
        for line in lines:
            if line in angr_lines:
                order_hit += 1
                # print("命中", addr, line)
            else:
                order_miss += 1
                # print("miss", addr, line)
    print("命中率为", "%.2f%%" % (order_hit/(order_hit+order_miss)*100))
    

# print("命中率为", "%.2f%%" % (12/(15)*100))