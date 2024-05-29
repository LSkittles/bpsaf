import pyvex

from TargetFacts import TargetFacts



def getTmpEid(irsb_addr, tmp, facts:TargetFacts):
    if (irsb_addr, tmp) not in facts.tmp_vex_exp:
        return -1
    return facts.tmp_vex_exp[(irsb_addr, tmp)][0]
def getTmpSize(irsb_addr, tmp, facts:TargetFacts):
    if (irsb_addr, tmp) not in facts.tmp_vex_exp:
        return -1
    return facts.tmp_vex_exp[(irsb_addr, tmp)][1]
def getConsEid(con, facts:TargetFacts, eid_iter):
    # 有时候会出现t12 = nan的情况
    # 通常出现在ite语句中iftrue、iffalse位置
    # 将其作为一个size为0，value为0的特殊常量
    # 浮点数常量pass
    # 还有t12 = 0这种情况（0，不是0x00000000，size也是0）
    if con.size is None:
        size = 0
        value = 0
    elif type(con.value) is float:
        return -1
    else:
        size = con.size
        value = con.value
    if (size, value) not in facts.const_vex_exp:
        facts.const_vex_exp[(size, value)] = next(eid_iter)
    return facts.const_vex_exp[(size, value)]
def getRegEid(offset, byte_number, facts:TargetFacts, eid_iter):
    # angr提供了一个(offset, size)到regname的转化函数，可以直接hack进去看一下转换原理
    # 实际翻译的时候VEX IR里会有168这种只有偏移值，没有对应寄存器的put语句
    # vex ir会写成put(168) = 0x12345678
    # 还有一些size为0的情况出现，目前不确定是angr还是谁的问题。
    # 这里处理方式很粗暴，直接把没有regname的以及size是0的全部扔掉了，需要的话可以重新修改一下
    # 这里如果(offset, size)如果不在register_size_names里，size全部重置成0
    if (offset, byte_number) not in facts.arch.register_size_names:
        byte_number = 0
    if offset == -1 or byte_number == -1 or byte_number == 0:
        return -1
    if (offset, byte_number) not in facts.reg_vex_exp:
        new_eid = next(eid_iter)
        facts.reg_vex_exp[(offset, byte_number)] = new_eid
        facts.regname_vex_exp[facts.arch.translate_register_name(offset, byte_number)] = new_eid
    return facts.reg_vex_exp[(offset, byte_number)]
def getBinopEid(bit_number, bvec, arg0_eid, arg1_eid, facts:TargetFacts, eid_iter):
    if arg0_eid == -1 or arg1_eid == -1:
        return -1
    if (bit_number, bvec, arg0_eid, arg1_eid) not in facts.binop_vex_exp:
        facts.binop_vex_exp[(bit_number, bvec, arg0_eid, arg1_eid)] = next(eid_iter)
    return facts.binop_vex_exp[(bit_number, bvec, arg0_eid, arg1_eid)]
def getUnopEid(bit_number, nvec, data_eid, facts:TargetFacts, eid_iter):
    if data_eid == -1:
        return -1
    if (bit_number, nvec, data_eid) not in facts.unop_vex_exp:
        facts.unop_vex_exp[(bit_number, nvec, data_eid)] = next(eid_iter)
    return facts.unop_vex_exp[(bit_number, nvec, data_eid)]
def getITEEid(bit_number, cond_eid, iftrue_eid, iffalse_eid, facts:TargetFacts, eid_iter):
    if cond_eid == -1 or iftrue_eid == -1 or iffalse_eid == -1:
        return -1
    if (bit_number, cond_eid, iftrue_eid, iffalse_eid) not in facts.ite_vex_exp:
        facts.ite_vex_exp[(bit_number, cond_eid, iftrue_eid, iffalse_eid)] = next(eid_iter)
    return facts.ite_vex_exp[(bit_number, cond_eid, iftrue_eid, iffalse_eid)]
def getLoadEid(byte_number, addr_eid, endness, facts:TargetFacts, eid_iter):
    if (byte_number == -1) | (addr_eid == -1):
        return -1
    if (byte_number, addr_eid, endness) not in facts.mem_vex_exp:
        facts.mem_vex_exp[(byte_number, addr_eid, endness)] = next(eid_iter)
    return facts.mem_vex_exp[(byte_number, addr_eid, endness)]


def getArgEid(arg, irsb_addr, facts, eid_iter):
    # arg要么tmp，要么cons，计算其eid
    if arg.tag == 'Iex_RdTmp':
        return getTmpEid(irsb_addr, arg.tmp, facts)
    elif arg.tag == 'Iex_Const':
        return getConsEid(arg.con, facts, eid_iter)
    else:
        return -1
def getArgSize_Bit(arg, irsb_addr, facts):
    if arg.tag == 'Iex_RdTmp':
        return getTmpSize(irsb_addr, arg.tmp, facts)
    elif arg.tag == 'Iex_Const':
        if arg.con.size is None:
            return 0
        else:
            return arg.con.size
    else:
        return -1

# pyvex.expr.Binop
# binop 表
# key=tag, value=(bit_number, bvec)
# bpa用于生成mba ir时应该只关注地址运算，这里将浮点数与SIMD指令的运算符都忽略掉
# 但是vex ir里没找到ROL、ROR对应的运算符，暂且记下
BiNopDict = {
    # 全部改为单词形式，与vex ir保持一致
    'Iop_Add8': (8, "Add8"), 'Iop_Add16': (16, "Add16"), 'Iop_Add32': (32, "Add32"), 'Iop_Add64': (64, "Add64"),
    'Iop_Sub8': (8, "Sub8"), 'Iop_Sub16': (16, "Sub16"), 'Iop_Sub32': (32, "Sub32"), 'Iop_Sub64': (64, "Sub64"),
    'Iop_Mul8': (8, "Mul8"), 'Iop_Mul16': (16, "Mul16"), 'Iop_Mul32': (32, "Mul32"), 'Iop_Mul64': (64, "Mul64"),
    # MullU、MullS在后边
    'Iop_And8': (8, "And8"), 'Iop_And16': (16, "And16"), 'Iop_And32': (32, "And32"), 'Iop_And64': (64, "And64"),
    'Iop_Or8': (8, "Or8"), 'Iop_Or16': (16, "Or16"), 'Iop_Or32': (32, "Or32"), 'Iop_Or64': (64, "Or64"),
    'Iop_Xor8': (8, "Xor8"), 'Iop_Xor16': (16, "Xor16"), 'Iop_Xor32': (32, "Xor32"), 'Iop_Xor64': (64, "Xor64"),
    # 数据以补码形式存放，所以算术左移与逻辑左移等价？目前想不明白，先这样。
    'Iop_Shl8': (8, "Shl8"), 'Iop_Shl16': (16, "Shl16"), 'Iop_Shl32': (32, "Shl32"), 'Iop_Shl64': (64, "Shl64"),
    'Iop_Shr8': (8, "Shr8"), 'Iop_Shr16': (16, "Shr16"), 'Iop_Shr32': (32, "Shr32"), 'Iop_Shr64': (64, "Shr64"),
    'Iop_Sar8': (8, "Sar8"), 'Iop_Sar16': (16, "Sar16"), 'Iop_Sar32': (32, "Sar32"), 'Iop_Sar64': (64, "Sar64"),
    'Iop_DivU32': (32, "DivU32"),
    'Iop_DivS32': (32, "DivS32"),
    'Iop_DivU64': (64, "DivU64"),
    'Iop_DivS64': (64, "DivS64"),
    'Iop_DivU32E': (32, "DivU32E"),
    'Iop_DivS32E': (32, "DivS32E"),
    'Iop_DivU64E': (64, "DivU64E"),
    'Iop_DivS64E': (64, "DivS64E"),
    'Iop_DivModU64to32': (64, "DivModU64to32"), 'Iop_DivModU128to64': (128, "DivModU128to64"),
    'Iop_DivModS64to32': (64, "DivModS64to32"), 'Iop_DivModS128to64': (128, "DivModS128to64"),
    'Iop_DivModS64to64': (128, "DivModS64to32"),
    
    'Iop_MullS8': (16, "MullS8"), 'Iop_MullS16': (32, "MullS16"), 'Iop_MullS32': (64, "MullS32"), 'Iop_MullS64': (128, "MullS64"),
    'Iop_MullU8': (16, "MullU8"), 'Iop_MullU16': (32, "MullU16"), 'Iop_MullU32': (64, "MullU32"), 'Iop_MullU64': (128, "MullU64"),
    
    # 一些二元的convert运算
    'Iop_8HLto16': (16, '8HLto16'), 'Iop32HLto64': (64, '32HLto64'), 'Iop64HLto128': (128, '64HLto128'),
    
    # compare运算
    'Iop_CmpEQ8': (1, 'CmpEQ8'), 'Iop_CmpEQ16': (1, 'CmpEQ16'), 'Iop_CmpEQ32': (1, 'CmpEQ32'), 'Iop_CmpEQ64': (1, 'CmpEQ64'),
    'Iop_CmpNE8': (1, 'CmpNE8'), 'Iop_CmpNE16': (1, 'CmpNE16'), 'Iop_CmpNE32': (1, 'CmpNE32'), 'Iop_CmpNE64': (1, 'CmpNE64'),
    
    # cas运算先pass掉
    
    # expensive的compare运算
    'Iop_ExpCmpNE8': (1, 'ExpCmpNE8'), 'Iop_ExpCmpNE16': (1, 'ExpCmpNE16'), 'Iop_ExpCmpNE32': (1, 'ExpCmpNE32'), 'Iop_ExpCmpNE64': (1, 'ExpCmpNE64'),
    
    # standard integer comparisons
    'Iop_CmpLT32S': (1, 'CmpLT32S'), 'Iop_CmpLT64S': (1, 'CmpLT64S'),
    'Iop_CmpLE32S': (1, 'CmpLE32S'), 'Iop_CmpLE64S': (1, 'CmpLE64S'),
    'Iop_CmpLT32U': (1, 'CmpLT32U'), 'Iop_CmpLT64U': (1, 'CmpLT64U'),
    'Iop_CmpLE32U': (1, 'CmpLE32U'), 'Iop_CmpLE64U': (1, 'CmpLE64U'),
}

# 一元运算表
UnopDict = {
    # 主要是vex ir中的convert运算，这里只处理整数运算
    # 还有一些convert运算是二元运算符，比如16HLto32，写入BiNopDict中。
    # widening
    'Iop_8Uto16': (16, "8Uto16"), 'Iop_8Uto32': (32, "8Uto32"), 'Iop_8Uto64': (64, "8Uto64"),
    'Iop_16Uto32': (32, "16Uto32"), 'Iop_16Uto64': (64, "16Uto64"),
    'Iop_32Uto64': (64, "32Uto64"),
    'Iop_8Sto16': (16, "8Sto16"), 'Iop_8Sto32': (32, "8Sto32"), 'Iop_8Sto64': (64, "8Sto64"),
    'Iop_16Sto32': (32, "16Sto32"), 'Iop_16Sto64': (64, "16Sto64"),
    'Iop_32Sto64': (64, "32Sto64"),
    # narrowing
    'Iop_64to8': (8, '64to8'), "Iop_32to8": (8, "32to8"), 'Iop_64to16': (16, "64to16"),
    'Iop_16to8': (8, '16to8'), 'Iop_16HIto8': (8, '16HIto8'),
    'Iop32to16': (16, '32to16'), 'Iop32HIto16': (16, '32HIto16'),
    'Iop64to32': (32, '64to32'), 'Iop64HIto32': (32, '64HIto32'),
    'Iop128to64': (64, '128to64'), 'Iop128HIto64': (64, '128HIto64'),
    # 1-bit stuff
    'Iop_Not1': (1, 'Not1'),
    'Iop_32to1': (1, '32to1'),
    'Iop_64to1': (1, '64to1'),
    'Iop_1Uto8': (8, '1Uto8'),
    'Iop_1Uto16': (16, '1Uto16'),     # 不知道为什么，vex ir里有1Sto16，没有1Uto16，这里先加上，大不了不用。
    'Iop_1Uto32': (32, '1Uto32'),
    'Iop_1Uto64': (64, '1Uto64'),
    'Iop_1Sto8': (8, '1Sto8'),
    'Iop_1Sto16': (16, '1Sto16'),
    'Iop_1Sto32': (32, '1Sto32'),
    'Iop_1Sto64': (64, '1Sto64'),
    
    # not运算
    'Iop_Not8': (8, 'Not8'), 'Iop_Not16': (16, 'Not16'), 'Iop_Not32': (32, 'Not32'), 'Iop_Not64': (64, 'Not64'),
    
    # wierdo integer stuff
    'Iop_Clz32': (32, 'Clz32'), 'Iop_Clz64': (64, 'Clz64'),
    'Iop_Ctz32': (32, 'Ctz32'), 'Iop_Ctz64': (64, 'Ctz64'),
}


# size_byte 表
TypeDict_Byte = {
    'Ity_I8': 1, 'Ity_I16': 2, 'Ity_I32': 4, 'Ity_I64': 8, 'Ity_I128': 16
    # 其他的不予考虑
}

# size_bit 表
TypeDict_Bit = {
    'Ity_I1': 1, 'Ity_I8': 8, 'Ity_I16': 16, 'Ity_I32': 32, 'Ity_I64': 64, 'Ity_I128': 128
}

def computeBlockTmpEid(irsb:pyvex.IRSB, facts:TargetFacts, eid_iter):
    '''
    计算一个IRSB中所有tmp的eid，同时完成对IR表达式的编码。
    '''
    # 目前来看，临时变量是遵循严格的【先def-后use】，一轮循环即可
    stmts = irsb.statements
    irsb_addr = irsb.addr
    for stmt in stmts:
        if stmt.tag == 'Ist_WrTmp':     # 只考虑WrTmp语句
            eid = -1
            # 只考虑 GET\LOAD、部分整数运算与ITE运算，其余一律不予考虑，eid记为-1
            if stmt.data.tag == 'Iex_Get':
                # eg: t1 = GET:I32(EAX)
                # 将EAX的eid赋给tmp
                if stmt.data.type not in TypeDict_Byte:
                    eid = -1
                else:
                    byte_number = TypeDict_Byte[stmt.data.type]
                    eid = getRegEid(stmt.data.offset, byte_number, facts, eid_iter)
            elif stmt.data.tag == 'Iex_Load':
                if stmt.data.type not in TypeDict_Byte:
                    byte_number = -1
                else:
                    byte_number = TypeDict_Byte[stmt.data.type]
                addr_eid = getArgEid(stmt.data.addr, irsb_addr, facts, eid_iter)
                endness = stmt.data.endness
                eid = getLoadEid(byte_number, addr_eid, endness, facts, eid_iter)
            elif stmt.data.tag == 'Iex_Unop':
                if stmt.data.op not in UnopDict:
                    eid = -1
                else:
                    data_eid = getArgEid(stmt.data.args[0], irsb_addr, facts, eid_iter)
                    bit_number, nvec = UnopDict[stmt.data.op]
                    eid = getUnopEid(bit_number, nvec, data_eid, facts, eid_iter)
            elif stmt.data.tag == 'Iex_Binop':
                # eid = getBinArithEid(stmt.data, facts, eid_iter)
                if stmt.data.op not in BiNopDict:
                    eid = -1
                else:
                    arg0_eid = getArgEid(stmt.data.args[0], irsb_addr, facts, eid_iter)
                    arg1_eid = getArgEid(stmt.data.args[1], irsb_addr, facts, eid_iter)
                    bit_number, bvec = BiNopDict[stmt.data.op]
                    eid = getBinopEid(bit_number, bvec, arg0_eid, arg1_eid, facts, eid_iter)
            elif stmt.data.tag == 'Iex_ITE':
                cond_eid = getArgEid(stmt.data.cond, irsb_addr, facts, eid_iter)
                iftrue_eid = getArgEid(stmt.data.iftrue, irsb_addr, facts, eid_iter)
                iffalse_eid = getArgEid(stmt.data.iffalse, irsb_addr, facts, eid_iter)
                bit_number = max(getArgSize_Bit(stmt.data.iftrue, irsb_addr, facts),
                                 getArgSize_Bit(stmt.data.iffalse, irsb_addr, facts))
                eid = getITEEid(bit_number, cond_eid, iftrue_eid, iffalse_eid, facts, eid_iter)
            elif stmt.data.tag == 'Iex_RdTmp' or stmt.data.tag == 'Iex_Const':
                eid = getArgEid(stmt.data, irsb_addr, facts, eid_iter)
            else:
                pass
            
            tmp_type = irsb.tyenv.types[stmt.tmp]
            if tmp_type not in TypeDict_Bit:
                tmp_size = -1
            else:
                tmp_size = TypeDict_Bit[tmp_type]
            # 将计算得到的eid存于tmp表中
            facts.tmp_vex_exp[(irsb_addr, stmt.tmp)] = (eid, tmp_size)



def stmt_Put(irsb_addr, instruction_addr, ir_order, stmt:pyvex.IRStmt.Put, facts:TargetFacts, eid_iter):
    '''
    处理put类型的stmt
    '''
    data_eid = getArgEid(stmt.data, irsb_addr, facts, eid_iter)
    data_size_bit = getArgSize_Bit(stmt.data, irsb_addr, facts)
    loc_eid = getRegEid(stmt.offset, data_size_bit//8, facts, eid_iter)
    # data_eid为-1时，不写入表中
    if loc_eid != -1 and data_eid != -1 and data_size_bit != 0:
        facts.put_reg_vex.append((instruction_addr, ir_order, data_size_bit, data_eid, loc_eid))

def stmt_Store(irsb_addr, instruction_addr, ir_order, stmt:pyvex.IRStmt.Store, facts:TargetFacts, eid_iter):
    '''
    处理Store类型的stmt
    '''
    # addr
    # 同load，store的端序先不考虑
    addr_eid = getArgEid(stmt.addr, irsb_addr, facts, eid_iter)
    # data
    data_eid = getArgEid(stmt.data, irsb_addr, facts, eid_iter)
    data_size_bit = getArgSize_Bit(stmt.data, irsb_addr, facts)
    data_bytes = int(data_size_bit / 8)
    endness = stmt.endness
    # 若data_eid为-1，不写入表中
    # 由STle(t1) = 0（size为0的0）这种情况，好像可以处理，先放着吧
    if addr_eid != -1 and data_eid != -1 and data_size_bit != 0:
        facts.store_mem_vex.append((instruction_addr, ir_order, data_bytes, data_eid, addr_eid, endness))

def stmt_Exit(irsb_addr, instruction_addr, ir_order, stmt:pyvex.IRStmt.Exit, facts:TargetFacts, eid_iter):
    '''
    处理Exit类型的stmt
    '''
    guard_eid = getArgEid(stmt.guard, irsb_addr, facts, eid_iter)
    dst_eid = getConsEid(stmt.dst, facts, eid_iter)
    jumpkind = stmt.jumpkind
    offsIP = stmt.offsIP
    dst_size_bit = stmt.dst.size
    # regIP = facts.arch.translate_register_name(offsIP, int(dst_size_bit/4))
    IP_eid = getRegEid(offsIP, dst_size_bit//8, facts, eid_iter)
    if guard_eid != -1 and dst_eid != -1 and IP_eid != -1:
        facts.exit_vex.append((instruction_addr, ir_order, guard_eid, dst_eid, jumpkind, IP_eid))

def IRSB2Facts(irsb:pyvex.IRSB, facts:TargetFacts, eid_iter):
    '''
    将一个IRSB转化为对应的facts，并添加进当前的facts表中
    '''
    stmts = irsb.statements
    irsb_addr = irsb.addr
    instruction_addr = 0
    ir_order = 0

    computeBlockTmpEid(irsb, facts, eid_iter)
    
    for stmt in stmts:
        # 只考虑put、store与Imark语句，其余均不考虑
        if stmt.tag == 'Ist_IMark':
            ir_order = 0
            instruction_addr = stmt.addr
        elif stmt.tag == 'Ist_Put':
            ir_order += 1
            stmt_Put(irsb_addr, instruction_addr, ir_order, stmt, facts, eid_iter)
        elif stmt.tag == 'Ist_Store':
            ir_order += 1
            stmt_Store(irsb_addr, instruction_addr, ir_order, stmt, facts, eid_iter)
        elif stmt.tag == 'Ist_Exit':
            ir_order += 1
            stmt_Exit(irsb_addr, instruction_addr, ir_order, stmt, facts, eid_iter)
        else:
            ir_order += 1