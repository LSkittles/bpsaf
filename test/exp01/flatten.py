# 对VEX IR日志进行展平
import re
# import regex as re
from functools import partial

from memory_profiler import profile

# import os
# import resource

def tidyline(line: str):
    '''
    将每行line前的tab与空格，以及其他多余的字符去掉，最终返回
    '''
    # Ity语句
    ind = line.find('Ity')
    if ind != -1:
        return ''
    # if语句
    ind = line.find('if')
    if ind != -1:
        return ''
    # NEXT语句
    ind = line.find('NEXT')
    if ind != -1:
        return ''
    # abihint语句
    ind = line.find('AbiHint')
    if ind != -1:
        return ''
    # 01 | t1 = 0x21
    ind = line.find('|')
    if ind != -1:
        new_line = line[ind + 2:]
    else:
        new_line = line
    return re.sub(r'^\s+', '', new_line)


def replace_eid(match, t_dict):
    if match.group() in t_dict.keys():
        return t_dict[match.group()]
    else:
        return ''


# @profile
def flattenExp(exp, tmp_dict=None):
    '''
    查找表达式中存在的EID（表达式没有等号）
    '''
    # return exp
    # 如果有括号，将括号拆出来
    ind = exp.find('(')  # 按理只有一个括号
    exp_list = []
    if ind != -1:
        exp_list.append(exp[:ind + 1])
        new_exp = exp[ind + 1:]
    else:
        new_exp = exp
    # 将十六进制数字单独拆出来
    matches = re.finditer(pattern=r'0x[0-9A-Fa-f]+', string=new_exp)
    end = 0
    for match in matches:
        exp_list.append(new_exp[end:match.start()])
        exp_list.append(new_exp[match.start():match.end()])
        end = match.end()
    exp_list.append(new_exp[end:])
    
    l = len(exp_list)
    i = 0
    while i < l:
        tmp_exp = exp_list[i]
        # 字符串不是运算符，即没有括号
        ind1 = tmp_exp.find('(')
        # 字符串不是十六进制数字，即不存在0x
        ind2 = tmp_exp.find('0x')
        if ind1 == -1 and ind2 == -1:
            tmp_exp_2 = re.sub(pattern=r'[e][0-9]+|[t][0-9]+', repl=partial(replace_eid, t_dict=tmp_dict), string=tmp_exp)
        else:
            tmp_exp_2 = tmp_exp
        exp_list[i] = tmp_exp_2
        i += 1
    flattened_exp = ''.join(exp_list)
    # 好像就是正常展开的结果？
    # 如果过长就不处理了，直接返回空串算了
    if len(flattened_exp) > 20_000_000:
        return ''
    else:
        return flattened_exp


# @profile
def flatten_log(log_file_path, flatten_log_file_path):
    '''
    展平rebuild的log
    '''
    log = open(log_file_path, 'r')
    lines = log.readlines()
    log.close()
    sa = []
    tmp_dict = {}  # 存放块内的临时存量及flatten后的表达式
    for line in lines:
        new_line = tidyline(line)
        if new_line == '':
            continue
        # IRSB {
        ind = new_line.find('IRSB')
        if ind != -1:
            tmp_dict = {}
            sa.append(new_line.rstrip("\n"))
            continue
        # }
        if new_line == '}' or new_line == '}\n':
            sa.append('}')
            continue
        # IMark
        ind = new_line.find('IMark')
        if ind != -1:
            # 匹配左括号后，逗号或者右括号前的第一个字串
            sa.append('\t' + new_line.rstrip("\n"))
            continue
        # stmt
        ind = new_line.find('=')
        if ind != -1:
            left = new_line.split()[0]
            exp = new_line.split()[2]
            new_exp = flattenExp(exp, tmp_dict)
            # 处理stmt
            if re.fullmatch(pattern=r'[e][0-9]+|[t][0-9]+', string=left):
                # 写寄存器stmt则加入dict
                tmp_dict[left] = new_exp
            else:
                # 其他stmt则写入文本
                # 展开left
                new_left = flattenExp(left, tmp_dict)
                sa.append("\t" + new_left + " = " + new_exp)
    
    del lines
    flatten_log = open(flatten_log_file_path, 'w')
    flatten_log.write('\n'.join(sa))
    flatten_log.close()
    
    # # 将最大内存限制转换为字节
    # max_memory_bytes = 1000 * 1024 * 1024
    # # 获取当前进程的内存限制信息
    # soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    # # 设置新的内存限制
    # resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, hard))