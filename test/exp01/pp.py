# 根据生成的facts还原出部分的VEX IR，验证生成结果的正确性。
import os
import sys
from collections import defaultdict
import archinfo
import pickle

from test.exp01.tempFacts import tempFacts

def readFacts(source_dir, facts:tempFacts):
    '''
    从source_dir中读取facts，并生成对应的列表与词典
    facts需指定archinfo
    生成到tempFacts中
    '''
    # put_reg_vex表
    put_reg = []
    put_reg_file = open(os.path.join(source_dir, "put_reg_vex.facts"), "r")
    lines = put_reg_file.readlines()
    for line in lines:
        addr = int(line.split()[0], 10)
        order = line.split()[1]
        size_bit = line.split()[2]
        data = line.split()[3]
        regname = line.split()[4]
        put_reg.append((addr, order, size_bit, data, regname))
    put_reg_file.close()
    facts.put_reg_vex = put_reg
    # store_mem_vex表
    store_mem = []
    store_mem_file = open(os.path.join(source_dir, "store_mem_vex.facts"), "r")
    lines = store_mem_file.readlines()
    for line in lines:
        addr = int(line.split()[0], 10)
        order = line.split()[1]
        byte_number = line.split()[2]
        data = line.split()[3]
        mem = line.split()[4]
        endness = line.split()[5]
        store_mem.append((addr, order, byte_number, data, mem, endness))
    store_mem_file.close()
    facts.store_mem_vex = store_mem
    # reg_vex_exp表
    regname_vex = {}
    reg_vex_file = open(os.path.join(source_dir, "regname_vex_exp.facts"), "r")
    lines = reg_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        regname = line.split()[1].lower()
        regname_vex[eid] = regname
    reg_vex_file.close()
    facts.regname_vex_exp = regname_vex
    # mem_vex_exp表
    mem_vex = {}
    mem_vex_file = open(os.path.join(source_dir, "mem_vex_exp.facts"), "r")
    lines = mem_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        byte_number = line.split()[1]
        data = line.split()[2]
        endness = line.split()[3]
        mem_vex[eid] = (byte_number, data, endness)
    mem_vex_file.close()
    facts.mem_vex_exp = mem_vex
    # const_vex_exp表
    const_vex = {}
    const_vex_file = open(os.path.join(source_dir, "const_vex_exp.facts"), "r")
    lines = const_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        size_bit = line.split()[1]
        value = int(line.split()[2], 10)
        const_vex[eid] = (size_bit, value)
    const_vex_file.close()
    facts.const_vex_exp = const_vex
    # unop_vex_exp表
    unop_vex = {}
    unop_vex_file = open(os.path.join(source_dir, "unop_vex_exp.facts"), "r")
    lines = unop_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        size_bit = line.split()[1]
        unop = line.split()[2]
        arg = line.split()[3]
        unop_vex[eid] = (size_bit, unop, arg)
    unop_vex_file.close()
    facts.unop_vex_exp = unop_vex
    # binop_vex_exp表
    binop_vex = {}
    binop_vex_file = open(os.path.join(source_dir, "binop_vex_exp.facts"), "r")
    lines = binop_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        size_bit = line.split()[1]
        binop = line.split()[2]
        arg0 = line.split()[3]
        arg1 = line.split()[4]
        binop_vex[eid] = (size_bit, binop, arg0, arg1)
    binop_vex_file.close()
    facts.binop_vex_exp = binop_vex
    # ite_vex_exp表
    ite_vex = {}
    ite_vex_file = open(os.path.join(source_dir, "ite_vex_exp.facts"), "r")
    lines = ite_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        size_bit = line.split()[1]
        arg0 = line.split()[2]
        arg1 = line.split()[3]
        arg2 = line.split()[4]
        ite_vex[eid] = (size_bit, arg0, arg1, arg2)
    ite_vex_file.close()
    facts.ite_vex_exp = ite_vex
    # tmp_vex_exp表
    tmp_vex = {}
    tmp_vex_file = open(os.path.join(source_dir, "tmp_vex_exp.facts"), "r")
    lines = tmp_vex_file.readlines()
    for line in lines:
        eid = line.split()[0]
        tmp_size_bit = line.split()[1]
        irsb_addr = int(line.split()[2], 10)
        tmp = line.split()[3]
        tmp_vex[eid] = (irsb_addr, tmp, tmp_size_bit)
        # tmp_vex[(eid, irsb_addr)] = (tmp, tmp_size_bit)
    tmp_vex_file.close()
    facts.tmp_vex_exp = tmp_vex
    # exit表
    exit_vex = []
    exit_vex_file = open(os.path.join(source_dir, "exit_vex.facts"), "r")
    lines = exit_vex_file.readlines()
    for line in lines:
        addr = int(line.split()[0], 10)
        order = line.split()[1]
        guard = line.split()[2]
        dst = line.split()[3]
        jumpkind = line.split()[4]
        offsIP = line.split()[5]
        exit_vex.append((addr, order, guard, dst, jumpkind, offsIP))
    exit_vex_file.close()
    facts.exit_vex = exit_vex
    #bin_cfg
    bin_cfg = pickle.load( file = open(os.path.join(source_dir, "bin_cfg.pickle"), 'rb') )
    facts.bin_cfg = bin_cfg
    # arch
    bin_arch = pickle.load( file = open(os.path.join(source_dir, "bin_arch.pickle"), 'rb') )
    facts.arch = bin_arch
    
    # return put_reg, store_mem, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex, bin_cfg
    # return facts

def searchFacts(data_eid, target_list, reg_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex):
    '''
    从facts中递归查找相关的stmt，将其添加入target_list中
    '''
    opened = []
    closed = []
    opened.append(data_eid)
    while opened:
        # print(target_list[0][1][0])
        eid = opened[0]
        if eid in reg_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('reg', (eid, reg_vex[eid])))
        elif eid in mem_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('mem', (eid, mem_vex[eid])))
            if mem_vex[eid][1] not in closed:
                opened.append(mem_vex[eid][1])
            # opened.append(mem_vex[eid][1])
        elif eid in const_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('const', (eid, const_vex[eid])))
        elif eid in unop_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('unop', (eid, unop_vex[eid])))
            if unop_vex[eid][2] not in closed:
                opened.append(unop_vex[eid][2])
            # opened.append(unop_vex[eid][2])
        elif eid in binop_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('binop', (eid, binop_vex[eid])))
            if binop_vex[eid][2] not in closed:
                opened.append(binop_vex[eid][2])
            if binop_vex[eid][3] not in closed:
                opened.append(binop_vex[eid][3])
            # opened.append(binop_vex[eid][2])
            # opened.append(binop_vex[eid][3])
        elif eid in ite_vex:
            opened.remove(eid)
            closed.append(eid)
            target_list.append(('ite', (eid, ite_vex[eid])))
            if ite_vex[eid][1] not in closed:
                opened.append(ite_vex[eid][1])
            if ite_vex[eid][2] not in closed:
                opened.append(ite_vex[eid][2])
            if ite_vex[eid][3] not in closed:
                opened.append(ite_vex[eid][3])
            # opened.append(ite_vex[eid][1])
            # opened.append(ite_vex[eid][2])
            # opened.append(ite_vex[eid][3])
        else:
            opened.remove(eid)

def int2hex(value, length):
    '''
    
    '''
    hex_str = hex(value)[2:]
    while len(hex_str) < length:
        hex_str = '0' + hex_str
    hex_str = '0x' + hex_str
    return hex_str

def tranEID2exp(eid, facts:tempFacts):
    '''
    将facts中的eid替换为tmp或常量，以便打印
    输入的eid为字符串，形式为“e12”
    '''
    if eid in facts.tmp_vex_exp:
        # return 't' + str(facts.tmp_vex_exp[eid][1])
        return eid
    elif eid in facts.const_vex_exp:
        size_bit = int(facts.const_vex_exp[eid][0])
        value = facts.const_vex_exp[eid][1]
        if size_bit == 0:
            return "nan"
        else:
            return int2hex(value, size_bit//4)
    else:
        raise Exception("未知eid")

def stmt_print(stmt, regname_vex, reg_dicts, facts:tempFacts):
    '''
    打印单独的stmt
    '''
    if stmt[0] == 'put':
        # ('put', (addr, order, size_bit, data, reg))
        # sa = hex(stmt[1][0]) + ':' + '\t'
        sa = '\t'
        sa += 'PUT(' + regname_vex[stmt[1][4]] + ')' + ' = ' + stmt[1][3]
        print(sa)
    elif stmt[0] == 'store':
        # ('store', (addr, order, size_byte, data, mem, endness))
        # sa = hex(stmt[1][0]) + ':' + '\t'
        sa = '\t'
        if stmt[1][5] == 'Iend_LE':
            sa += 'STle'
        else:
            sa += 'STbe'
        sa += '(' + stmt[1][4] + ')' + ' = ' + stmt[1][3]
        print(sa)
    elif stmt[0] == 'reg':
        # ('reg', (eid, reg_name))
        sa = '\t'
        sa += stmt[1][0] + ' = ' + 'GET:I' + str(reg_dicts[ stmt[1][1].lower() ][1]*8) + '(' + stmt[1][1] + ')'
        print(sa)
    elif stmt[0] == 'mem':
        # ('mem', (eid, (size_byte, data, endness)))
        sa = '\t'
        sa += stmt[1][0] + ' = '
        if stmt[1][1][2] == 'Iend_LE':
            sa += 'LDle:I'
        else:
            sa += 'LDbe:I'
        sa += str(int(stmt[1][1][0])*8) +'(' + stmt[1][1][1] + ')'
        print(sa)
    elif stmt[0] == 'const':
        # ('const', (eid, (size_bit, value)))
        sa = '\t'
        sa += stmt[1][0] + ' = '
        # nan需要特殊处理
        if stmt[1][1][0] == 0:
            sa += 'nan'
        else:
            sa += int2hex(stmt[1][1][1], int(stmt[1][1][0])//4)
        print(sa)
    elif stmt[0] == 'unop':
        # ('unop', (eid, (size_bit, unop, arg)))
        sa = '\t'
        sa += stmt[1][0] + ' = ' + stmt[1][1][1] + '(' + stmt[1][1][2] + ')'
        print(sa)
    elif stmt[0] == 'binop':
        # ('binop', (eid, (size_bit, binop, arg0, arg1)))
        sa = '\t'
        sa += stmt[1][0] + ' = ' + stmt[1][1][1] + '(' + stmt[1][1][2] + ',' + stmt[1][1][3] + ')'
        print(sa)
    elif stmt[0] == 'ite':
        # ('ite', (eid, (size_bit, arg0, arg1, arg2)))
        sa = '\t'
        sa += stmt[1][0] + ' = ' + 'ITE' + '(' + stmt[1][1][1] + ',' + stmt[1][1][2] + ',' + stmt[1][1][3] + ')'
        print(sa)
    elif stmt[0] == 'exit':
        # ('exit', (addr, order, guard, dst, jumpkind, offsIP))
        sa = '\t'
        sa += 'if (' + stmt[1][2] + ')'
        # 获取dst的size_byte，进而将offsIP翻译为regname
        sa += ' { PUT(' + regname_vex[stmt[1][5]] + ') = ' + stmt[1][3] + '; ' + stmt[1][4] + ' }'
        print(sa)
    else:
        pass


def sa_print(stmt_pp_dict, regname_vex, reg_dicts, bin_cfg, facts):
    '''
    将生成的stmt_pp_dict打印到控制台上
    '''
    # 给地址排下序，按照从小到大的顺序print
    addrs = list(stmt_pp_dict.keys())
    addrs.sort()
    for block_addr, ins_list in bin_cfg.items():
        # 清理掉block中重复的stmt
        block_pp_list = []
        block_stmt_pp_list = defaultdict(list)
        for ins_addr in ins_list:
            if ins_addr in stmt_pp_dict:
                stmt_pp_list = stmt_pp_dict[ins_addr]
            else:
                stmt_pp_list = []
            # 如果stmt已经在block中出现，则不再print
            for stmt_pp in stmt_pp_list:
                if stmt_pp not in block_pp_list:
                    block_pp_list.append(stmt_pp)
                    block_stmt_pp_list[ins_addr].append(stmt_pp)

        print('IRSB {' )
        for ins_addr in block_stmt_pp_list:
            print('\t------IMark(' + str(hex(ins_addr)) + ')------')
            stmts =  block_stmt_pp_list[ins_addr]
            for stmt in stmts:
                stmt_print(stmt, regname_vex, reg_dicts, facts)
        print('}')

def sort_list(pp_list:list):
    '''
    将写寄存器语句全部按ID排序
    '''
    tmp_list_1 = []
    tmp_list_2 = []
    for i in pp_list:
        if i[0] == 'put' or i[0] == 'store' or i[0] == 'exit':
            tmp_list_2.append(i)
        else:
            tmp_list_1.append(i)
    # 冒泡排序
    len1 = len(tmp_list_1)
    for i in range(0, len1):
        for j in range(i, len1):
            num_i = int(tmp_list_1[i][1][0][1:])
            num_j = int(tmp_list_1[j][1][0][1:])
            if num_i > num_j:
                tmp = tmp_list_1[i]
                tmp_list_1[i] = tmp_list_1[j]
                tmp_list_1[j] = tmp
    pp_list = tmp_list_1 + tmp_list_2
    return pp_list
        
def pp(source_dir):
    facts = tempFacts()
    # facts.arch = arch
    readFacts(source_dir, facts)
    reg_dicts = facts.arch.registers
    # put_reg, store_mem, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex, bin_cfg = readFacts(source_dir)
    put_reg = facts.put_reg_vex
    store_mem = facts.store_mem_vex
    regname_vex = facts.regname_vex_exp
    mem_vex = facts.mem_vex_exp
    const_vex = facts.const_vex_exp
    unop_vex = facts.unop_vex_exp
    binop_vex = facts.binop_vex_exp
    ite_vex = facts.ite_vex_exp
    tmp_vex = facts.tmp_vex_exp
    exit_vex = facts.exit_vex
    
    bin_cfg = facts.bin_cfg
    
    
    # 对读取的facts进行处理，存放进stmt_pp_dict中，以便稍后print
    # key=stmt_addr, value=需要print的stmt组成的list
    stmt_pp_dict = defaultdict(list)
    
    for put_stmt in put_reg:
        addr = put_stmt[0]
        data_eid = put_stmt[3]
        # tmp_list = []
        # searchFacts(data_eid, tmp_list, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        # tmp_list.reverse()
        # stmt_pp_dict[addr] += tmp_list
        stmt_pp_dict[addr].append(('put', put_stmt))
        searchFacts(data_eid, stmt_pp_dict[addr], regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
    for store_stmt in store_mem:
        addr = store_stmt[0]
        data_eid = store_stmt[3]
        addr_eid = store_stmt[4]
        # tmp_list = []
        # searchFacts(addr_eid, tmp_list, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        # tmp_list.reverse()
        # stmt_pp_dict[addr] += tmp_list
        # tmp_list = []
        # searchFacts(data_eid, tmp_list, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        # tmp_list.reverse()
        # stmt_pp_dict[addr] += tmp_list
        stmt_pp_dict[addr].append(('store', store_stmt))
        searchFacts(addr_eid, stmt_pp_dict[addr], regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        searchFacts(data_eid, stmt_pp_dict[addr], regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
    for exit_stmt in exit_vex:
        addr = exit_stmt[0]
        guard = exit_stmt[2]
        dst = exit_stmt[3]
        # tmp_list = []
        # searchFacts(guard, tmp_list, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        # tmp_list.reverse()
        # stmt_pp_dict[addr] += tmp_list
        # tmp_list = []
        # searchFacts(dst, tmp_list, regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        # tmp_list.reverse()
        # stmt_pp_dict[addr] += tmp_list
        stmt_pp_dict[addr].append(('exit', exit_stmt))
        searchFacts(guard, stmt_pp_dict[addr], regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
        searchFacts(dst, stmt_pp_dict[addr], regname_vex, mem_vex, const_vex, unop_vex, binop_vex, ite_vex)
    for addr, stmt_pp_list in stmt_pp_dict.items():
        # stmt_pp_list.reverse()
        # 将写寄存器语句全部按ID排序
        stmt_pp_dict[addr] = sort_list(stmt_pp_list)
    
    sa_print(stmt_pp_dict, regname_vex, reg_dicts, bin_cfg, facts)
    # print('print end')
    

# binary_path = open("../../results/pp/bhe_bzip2-0512-03.txt", 'w')
# sys.stdout = binary_path
# pp("../../results/bhe/401.bzip2_O0_gcc")