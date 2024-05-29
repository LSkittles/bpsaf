# pretty print用
# 用于存放从Datalog事实中还原出来的数据
class tempFacts:
    def __init__(self):
        # archinfo
        self.arch = None
        
        # put_reg_vex(addr, order, bit_number, data_eid, reg_eid)
        # src与des跟论文中的顺序相反
        self.put_reg_vex = []
        
        # store_mem_vex(addr, order, byte_number, data_eid, addr_eid, endness)
        # src与des跟论文中的顺序相反
        self.store_mem_vex = []
        
        # vex ir中reg是由offset与size两个值确定的，encode时也需要考虑到size
        # 为与bpa原先的实现保持一致，额外引入一个offset_vex_exp表用于encode
        # offet_vex_exp(eid, offset, byte_number)
        # key=(offset, byte_number), value=eid
        # 然后再根据offset_vex_exp表，生成更符合bpa形式的reg_vex_exp表
        # key=reg_name, value=eid
        self.reg_vex_exp = {}
        self.regname_vex_exp = {}
        
        # mem_vex_exp(eid, byte_number, addr_eid, endness)
        # key=(byte_number, addr_exp, endness), value=eid
        # 似更应命名mem_rtl_eid
        self.mem_vex_exp = {}
        
        # const_vex_exp(eid, bit_number, cons)
        # key=(bit_number, cons), value=eid
        self.const_vex_exp = {}
        
        # 用以存放vex ir中出现的一元运算
        # unop_vex_exp(eid, bit_number, uvec, data_eid)
        # key=(bit_number, nvec, data_eid), value=eid
        self.unop_vex_exp = {}
        # 用以存放vex ir出现的二元运算
        # 除ITE外，三元、四元运算目前看好像都是些浮点数与SIMD指令，都pass掉
        # binop_vex_exp(eid, bit_number, bvec, arg0_eid, arg1_eid)
        # key=(bit_number, bvec, arg0_eid, arg1_eid), value=eid，下同
        self.binop_vex_exp = {}
        # 用于存放vex ir中出现的ITE运算
        # ite_vex_exp(eid, bit_number, cond_eid, iftrue_eid, iffalse_eid)
        # key=(bit_number, cond_eid, iftrue_eid, iffalse_eid), value=eid
        self.ite_vex_exp = {}
        
        # 用以存放临时变量的eid，仅用于辅助计算。
        # tmp_vex_exp(eid, tmp_size, irsb_addr, tmp)
        # key=(irsb_addr, tmp), value=(eid, tmp_size)
        self.tmp_vex_exp = {}
        
        # exit_vex(addr, order, guard, dst, jumpkind, offsIP)
        self.exit_vex = []
        
        # 以后为辅助pretty print用
        # 用于存放程序的cfg
        # key=block的addr, value=block中指令的addr
        self.bin_cfg = {}
        
        self.reg_dicts = {}