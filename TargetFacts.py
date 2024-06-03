# 写论文的时候谓词进行了重新设计，所以谓词的名字跟BPA的不太一样
# 需要的话可能需要重构一下
# 不过目前建议直接修改后端部分，看起来会规整些

class TargetFacts:
    def __init__(self):
        # archinfo
        # 主要是从offset替换为相应的regname的时候用
        # 目前需要手动给赋值
        self.arch = None
        
        # 写寄存器
        # put_reg_vex(addr, order, bit_number, data_eid, reg_eid)
        self.put_reg_vex = []
        
        # 写内存
        # store_mem_vex(addr, order, byte_number, data_eid, addr_eid, endness)
        self.store_mem_vex = []
        
        # 条件跳转
        # exit_vex(addr, order, guard, dst, jumpkind, offsIP)
        self.exit_vex = []

        # 理论上来说之后的谓词是用于编码IR表达式的，
        # 但编码工作其实更倾向于对字符进行编码，同样一个reg可以被put，也可以被get
        # 因此这里不用get_reg这种有点歧义的词，直接就是reg_vex_exp
        # 之后mem_vex_exp同理，不使用store_mem_vex的名字
        # vex ir中reg是由offset与size两个值确定的，encode时也需要考虑到size
        # offet_vex_exp(eid, offset, byte_number)
        # key=(offset, byte_number), value=eid
        # 为与bpa原先的实现保持一致，额外引入一个regname_vex_exp表用于encode
        # regname_vex_exp(eid, regname)
        # key=regname, value=eid
        self.reg_vex_exp = {}
        self.regname_vex_exp = {}
        
        # mem_vex_exp(eid, byte_number, addr_eid, endness)
        # key=(byte_number, addr_exp, endness), value=eid
        self.mem_vex_exp = {}
        
        # const_vex_exp(eid, bit_number, cons)
        # key=(bit_number, cons), value=eid
        self.const_vex_exp = {}
        
        # 一元运算
        # unop_vex_exp(eid, bit_number, uvec, data_eid)
        # key=(bit_number, nvec, data_eid), value=eid
        self.unop_vex_exp = {}
        # 二元运算
        # 除ITE外，三元、四元运算目前看好像都是些浮点数与SIMD指令，都pass掉
        # binop_vex_exp(eid, bit_number, bvec, arg0_eid, arg1_eid)
        # key=(bit_number, bvec, arg0_eid, arg1_eid), value=eid，下同
        self.binop_vex_exp = {}
        # ITE运算
        # ite_vex_exp(eid, bit_number, cond_eid, iftrue_eid, iffalse_eid)
        # key=(bit_number, cond_eid, iftrue_eid, iffalse_eid), value=eid
        self.ite_vex_exp = {}
        
        # 用以存放临时变量的eid，仅用于辅助计算。
        # tmp_vex_exp(eid, tmp_size, irsb_addr, tmp)
        # key=(irsb_addr, tmp), value=(eid, tmp_size)
        self.tmp_vex_exp = {}
        
        # 仅用于pretty print
        self.bin_cfg = {}