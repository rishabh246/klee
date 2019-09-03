import sympy
import sympy.parsing.sympy_parser
#import inspect

mem  = {}
regs = {}
sym_cntr = 0
touched_locs = []

real_reg_vals = []
real_reg_vals_cntr = 1


def check(opcode, args, reg):
    global real_reg_vals_cntr
    if real_reg_vals_cntr == len(real_reg_vals):
        return
    if regs[reg] != real_reg_vals[real_reg_vals_cntr][reg]:
        print opcode, args, reg, regs[reg], real_reg_vals[real_reg_vals_cntr][reg]
    real_reg_vals_cntr += 1
    return

def print_touched_locs():
    global touched_locs
    #print len(touched_locs)
    touched_locs = list(set(touched_locs))
    offset_cntr = 0
    offsets = {}
    for i in range(len(touched_locs)):
        if type(touched_locs[i]) != int:
            temp = touched_locs[i].args
            if len(temp) > 1:
                for j in temp:
                    try:
                        if j.is_Mul and j not in offsets.keys():
                            offsets[j] = sympy.Symbol("offset_" + str(offset_cntr))
                            offset_cntr += 1
                        touched_locs[i] = touched_locs[i].subs(j, offsets[j])
                    except:
                        pass
    touched_locs = list(set(touched_locs))
    for i in touched_locs:
        print i


def init():
    global regs, mem, sym_cntr, real_reg_vals
    regs.clear()
    regs["rax"] = real_reg_vals[0]["rax"]#sympy.Symbol("rax")
    regs["rbx"] = real_reg_vals[0]["rbx"]#sympy.Symbol("rbx")
    regs["rdi"] = real_reg_vals[0]["rdi"]#sympy.Symbol("rdi")
    regs["rsi"] = real_reg_vals[0]["rsi"]#sympy.Symbol("rsi")
    regs["rdx"] = real_reg_vals[0]["rdx"]#sympy.Symbol("rdx")
    regs["rcx"] = real_reg_vals[0]["rcx"]#sympy.Symbol("rcx")
    regs["rbp"] = real_reg_vals[0]["rbp"]#sympy.Symbol("rbp")
    regs["rsp"] = real_reg_vals[0]["rsp"]#sympy.Symbol("rsp")
    regs["r8"]  = real_reg_vals[0]["r8"]#sympy.Symbol("r8")
    regs["r9"]  = real_reg_vals[0]["r9"]#sympy.Symbol("r9")
    regs["r10"] = real_reg_vals[0]["r10"]#sympy.Symbol("r10")
    regs["r11"] = real_reg_vals[0]["r11"]#sympy.Symbol("r11")
    regs["r12"] = real_reg_vals[0]["r12"]#sympy.Symbol("r12")
    regs["r13"] = real_reg_vals[0]["r13"]#sympy.Symbol("r13")
    regs["r14"] = real_reg_vals[0]["r14"]#sympy.Symbol("r14")
    regs["r15"] = real_reg_vals[0]["r15"]#sympy.Symbol("r15")
    sym_cntr = 0#16
    mem.clear()


def parse(ip_file):
    ins_list = []
    ctr = 0
    instruction_info_size = 18
    is_first = True
    with open(ip_file) as trace_file:
        t = {}
        for line in trace_file:
            text = line.rstrip()
            if(ctr % instruction_info_size > 0 and ctr % instruction_info_size < instruction_info_size-1):
                text = text.split(" = ")
                reg = text[0]
                val = text[1]
                if is_first:
                    val = int(val)
                else:
                    val = int(val, 16)
                t[reg] = val
            elif(ctr % instruction_info_size == instruction_info_size-1):
                is_first = False
                real_reg_vals.append(t)
                t = {}
                temp = line.split("|")[2].strip().split(" ", 1)
                opcode = temp[0]
                if opcode == "and":
                    opcode = "and_ins"
                elif opcode == "or":
                    opcode = "or_ins"
                elif opcode == "not":
                    opcode = "not_ins"
                args = ()
                if len(temp) > 1:
                    args = tuple(temp[1].split(", "))
                instr = (opcode, args)
                ins_list.append(instr)
            ctr = ctr + 1
    return ins_list


#### Helper Functions Start ####


def _get_sym_val():
    global sym_cntr
    val = sympy.Symbol("sym_" + str(sym_cntr))
    sym_cntr += 1
    return val


def _get_data_length(arg):
    if (arg in ["r14", "r9", "rcx", "rsi",
                "r10", "rbx", "rsp", "r11",
                "r8", "rdx", "rbp", "r15",
                "r12", "rdi", "rax", "r13"] or "qword" in arg):
        return 64
    elif (arg in ["r14d", "r9d", "ecx", "esi",
                "r10d", "ebx", "esp", "r11d",
                "r8d", "edx", "ebp", "r15d",
                "r12d", "edi", "eax", "r13d"] or "dword" in arg):
        return 32
    elif (arg in ["r14w", "r9w", "cx", "si",
                "r10w", "bx", "sp", "r11w",
                "r8w", "dx", "bp", "r15w",
                "r12w", "di", "ax", "r13w"] or "word" in arg):
        return 16
    elif (arg in ["r14b", "r9b", "cb", "sil",
                "r10b", "bl", "spl", "r11b",
                "r8b", "dl", "bpl", "r15b",
                "r12b", "dil", "al", "r13b"] or "byte" in arg):
        return 8
    return 64


def _is_ptr(x):
    if "ptr" in x:
        return True
    return False


def _is_literal(x):
    if "0x" in x:
        return True
    return False


def _get_arg(x):
    reg_mappings = [("eax", "rax"), ("ax", "rax"), ("al", "rax"),
                    ("ebx", "rbx"), ("bx", "rbx"), ("bl", "rbx"),
                    ("ecx", "rcx"), ("cx", "rcx"), ("cl", "rcx"),
                    ("edx", "rdx"), ("dx", "rdx"), ("dl", "rdx"),
                    ("esi", "rsi"), ("si", "rsi"), ("sil", "rsi"),
                    ("edi", "rdi"), ("di", "rdi"), ("dil", "rdi"),
                    ("ebp", "rbp"), ("bp", "rbp"), ("bpl", "rbp"),
                    ("esp", "rsp"), ("sp", "rsp"), ("spl", "rsp"),
                    ("r8d", "r8"), ("r8w", "r8"), ("r8b", "r8"),
                    ("r9d", "r9"), ("r9w", "r9"), ("r9b", "r9"),
                    ("r10d", "r10"), ("r10w", "r10"), ("r10b", "r10"),
                    ("r11d", "r11"), ("r11w", "r11"), ("r11b", "r11"),
                    ("r12d", "r12"), ("r12w", "r12"), ("r12b", "r12"),
                    ("r13d", "r13"), ("r13w", "r13"), ("r13b", "r13"),
                    ("r14d", "r14"), ("r14w", "r14"), ("r14b", "r14"),
                    ("r15d", "r15"), ("r15w", "r15"), ("r15b", "r15")]
    for i, j in reg_mappings:
        x = x.replace(i, j)
    x = x.replace("rr", "r")
    return x


def _write_mem(address, val):
    global mem
    touched_locs.append(address)
    mem[address] = val


def _write_reg(reg, val):
    global regs
    regs[reg] = val


def _read_mem(address, data_length=64):
    global mem
    touched_locs.append(address)
    if address not in mem.keys():
        val = _get_sym_val()
        mem[address] = val
    if data_length == 64:
        return mem[address]
    return mem[address] % 2**data_length


def _read_reg(reg, data_length=64):        
    if data_length == 64:
        return regs[reg]
    return regs[reg] % 2**data_length


def _touched_locs_append(address):
    global touched_locs
    touched_locs.append(address)


def _get_address(x):
    address = 0
    x = x.replace("-", "+-")
    x = x.split("ptr")[1].strip()[1:-1].split("+")
    for i in x:
        temp = i.split("*")
        acc = 1
        for j in temp:
            j = j.strip()
            if "-" == j[0]:
                sign = -1
                j = j[1:]
            else:
                sign = 1
            if (j in ["r14", "r9", "rcx", "rsi",
                      "r10", "rbx", "rsp", "r11",
                      "r8", "rdx", "rbp", "r15",
                      "r12", "rdi", "rax", "r13"]):
                acc *= _read_reg(j, 64)
            elif (j in ["r14d", "r9d", "ecx", "esi",
                        "r10d", "ebx", "esp", "r11d",
                        "r8d", "edx", "ebp", "r15d",
                        "r12d", "edi", "eax", "r13d"]):
                acc *= _read_reg(j, 32)
            elif (j in ["r14w", "r9w", "cx", "si",
                        "r10w", "bx", "sp", "r11w",
                        "r8w", "dx", "bp", "r15w",
                        "r12w", "di", "ax", "r13w"]):
                acc *= _read_reg(j, 16)
            elif (j in ["r14b", "r9b", "cb", "sil",
                        "r10b", "bl", "spl", "r11b",
                        "r8b", "dl", "bpl", "r15b",
                        "r12b", "dil", "al", "r13b"]):
                acc *= _read_reg(j, 8)
            else:
                acc *= int(j, 16)
            acc *= sign
        address += acc
    return address


def logical_rshift(val, n):
    return (val >> n) & (0x7fffffff >> (n - 1))


#### Helper Functions End   ####


#### Instruction Implementations Start ####


def push(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[0])
    val = _read_reg("rsp", 64) - 8
    _write_reg("rsp", val)
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, data_length)
        dst_address = _read_reg("rsp", 64)
        _write_mem(dst_address, val)
    elif _is_literal(src):
        dst_address = _read_reg("rsp", 64)
        val = int(src, 16)
        _write_mem(dst_address, val)
    else:
        dst_address = _read_reg("rsp", 64)
        val = _read_reg(src, data_length)
        _write_mem(dst_address, val)


def pop(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    dst = _get_arg(args[0])
    if _is_ptr(dst):
        src_address = _read_reg("rsp", 64)
        val = _read_mem(src_address, data_length)
        dst_address = _get_address(dst)
        _write_mem(dst_address, val)
    else:
        src_address = _read_reg("rsp", 64)
        val = _read_mem(src_address, data_length)
        _write_reg(dst, val)
    val = _read_reg("rsp", 64) + 8
    _write_reg("rsp", val)


def mov(args):
    global regs, mem
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, data_length)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = int(src, 16)
            _write_mem(dst_address, val)
        else:
            val = int(src, 16)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = _read_reg(src, data_length)
            _write_mem(dst_address, val)
        else:
            val = _read_reg(src, data_length)
            _write_reg(dst, val)
            

def lea(args):
    global regs, mem
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    src_address = _get_address(src)
    _write_reg(dst, src_address)


def add(args):
    global regs, mem
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_reg(dst, data_length) + _read_mem(src_address, data_length)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = _read_mem(dst_address, data_length) + int(src, 16)
            _write_mem(dst_address, val)
        else:
            val = _read_reg(dst, data_length) + int(src, 16)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = _read_mem(dst_address, data_length) + _read_reg(src, data_length)
            _write_mem(dst_address, val)
        else:
            val = _read_reg(dst,  data_length) + _read_reg(src, data_length)
            _write_reg(dst, val)


def sub(args):
    global regs, mem
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_reg(dst, data_length) - _read_mem(src_address, data_length)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = _read_mem(dst_address, data_length) - int(src, 16)
            _write_mem(dst_address, val)
        else:
            val = _read_reg(dst, data_length) - int(src, 16)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            val = _read_mem(dst_address, data_length) - _read_reg(src, data_length)
            _write_mem(dst_address, val)
        else:
            val = _read_reg(dst,  data_length) - _read_reg(src, data_length)
            _write_reg(dst, val)


def inc(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    dst = _get_arg(args[0])
    if _is_ptr(dst):
        dst_address = _get_address(dst)
        val = _read_mem(dst_address, data_length) + 1
        _write_mem(dst_address, val)
    else:
        val = _read_reg(dst, data_length) + 1
        _write_reg(dst, val)


def dec(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    dst = _get_arg(args[0])
    if _is_ptr(dst):
        dst_address = _get_address(dst)
        val = _read_mem(dst_address, data_length) - 1
        _write_mem(dst_address, val)
    else:
        val = _read_reg(dst, data_length) - 1
        _write_reg(dst, val)


def call(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[0])
    val = _read_reg("rsp", 64) - 8
    _write_reg("rsp", val)
    if _is_ptr(src):
        src_address = _get_address(src) 
        val = _read_mem(src_address, data_length)
        dst_address = _read_reg("rsp", 64)
        _write_mem(dst_address, val)
    elif _is_literal(src):
        dst_address = _read_reg("rsp", 64)
        val = int(src, 16)
        _write_mem(dst_address, val)
    else:
        dst_address = _read_reg("rsp", 64)
        val = _read_reg(src, data_length)
        _write_mem(dst_address, val)


def ret(args):
    global regs, mem
    src_address = _read_reg("rsp", 64)
    _read_mem(src_address, 64)
    val = _read_reg("rsp", 64) + 8
    _write_reg("rsp", val)


def xor(args):
    global regs, mem
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    class XOR(sympy.Function):
        nargs = (2,)
        @classmethod
        def eval(cls, arg1, arg2):
            if order(arg1,arg2):
                return XOR(arg2,arg1)
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        operand1 = _read_reg(dst, data_length)
        operand2 = _read_mem(src_address, data_length)
        try:
            operand1 = int(operand1)
            operand2 = int(operand2)
            val = operand1 ^ operand2
        except:
            try:
                operand1 = int(operand1)
                if operand1 == 0:
                    val = operand2
                else:
                    val = XOR(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    if operand2 == 0:
                        val = operand1
                    else:
                        val = XOR(operand1, operand2)
                except:
                    if operand1 == operand2:
                        val = 0
                    else:
                        val = XOR(operand1, operand2)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 ^ operand2
            except:
                if operand2 == 0:
                    val = operand1
                else:
                    val = XOR(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 ^ operand2
            except:
                if operand2 == 0:
                    val = operand1
                else:
                    val = XOR(operand1, operand2)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 ^ operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = XOR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = operand1
                        else:
                            val = XOR(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = 0
                        else:
                            val = XOR(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 ^ operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = XOR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = operand1
                        else:
                            val = XOR(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = 0
                        else:
                            val = XOR(operand1, operand2)
            _write_reg(dst, val)


def and_ins(args):
    global regs, mem
    class AND(sympy.Function):
        nargs = (2,)
        @classmethod
        def eval(cls, arg1, arg2):
            if str(arg1)>str(arg2):
                return AND(arg2,arg1)
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        operand1 = _read_reg(dst, data_length)
        operand2 = _read_mem(src_address, data_length)
        try:
            operand1 = int(operand1)
            operand2 = int(operand2)
            val = operand1 & operand2
        except:
            try:
                operand1 = int(operand1)
                if operand1 == 0:
                    val = 0
                else:
                    val = AND(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    if operand2 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    if operand1 == operand2:
                        val = operand1
                    else:
                        val = AND(operand1, operand2)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 & operand2
            except:
                if operand2 == 0:
                    val = 0
                else:
                    val = AND(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 & operand2
            except:
                if operand2 == 0:
                    val = 0
                else:
                    val = AND(operand1, operand2)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 & operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = 0
                        else:
                            val = AND(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = AND(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 & operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = 0
                        else:
                            val = AND(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = AND(operand1, operand2)
            _write_reg(dst, val)


def or_ins(args):
    global regs, mem
    class OR(sympy.Function):
        nargs = (2,)
        @classmethod
        def eval(cls, arg1, arg2):
            if str(arg1)>str(arg2):
                return OR(arg2,arg1)
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        operand1 = _read_reg(dst, data_length)
        operand2 = _read_mem(src_address, data_length)
        try:
            operand1 = int(operand1)
            operand2 = int(operand2)
            val = operand1 | operand2
        except:
            try:
                operand1 = int(operand1)
                if operand1 == 0:
                    val = operand2
                else:
                    val = OR(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    if operand2 == 0:
                        val = operand1
                    else:
                       val = OR(operand1, operand2)
                except:
                    if operand1 == operand2:
                        val = operand1
                    else:
                        val = OR(operand1, operand2)
        _write_reg(dst, val)
    elif _is_literal(src):
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 | operand2
            except:
                if operand2 == 0:
                    val = operand1
                else:
                    val = OR(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = int(src, 16)
            try:
                operand1 = int(operand1)
                val = operand1 | operand2
            except:
                if operand2 == 0:
                    val = operand1
                else:
                    val = OR(operand1, operand2)
            _write_reg(dst, val)
    else:
        if _is_ptr(dst):
            dst_address = _get_address(dst)
            operand1 = _read_mem(dst_address, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 | operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = OR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = operand1
                        else:
                           val = OR(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = OR(operand1, operand2)
            _write_mem(dst_address, val)
        else:
            operand1 = _read_reg(dst, data_length)
            operand2 = _read_reg(src, data_length)
            try:
                operand1 = int(operand1)
                operand2 = int(operand2)
                val = operand1 | operand2
            except:
                try:
                    operand1 = int(operand1)
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = OR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        if operand2 == 0:
                            val = operand1
                        else:
                           val = OR(operand1, operand2)
                    except:
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = OR(operand1, operand2)
            _write_reg(dst, val)


def not_ins(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    f = sympy.Function("NOT")
    dst = _get_arg(args[0])
    if _is_ptr(src):
        dst_address = _get_address(dst)
        operand = _read_mem(dst_address, data_length)
        try:
            operand = int(operand)
            val = ~operand
        except:
            val = f(operand)
        _write_reg(dst, val)
    else:
        operand = _read_reg(dst, data_length)
        try:
            operand = int(operand)
            val = ~operand
        except:
            val = f(operand)
        _write_reg(dst, val)


def neg(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        dst_address = _get_address(dst)
        val = -_read_mem(dst_address, data_length)
        _write_reg(dst, val)
    else:
        val = -_read_reg(dst, data_length)
        _write_reg(dst, val)


#### Check below.
def imul(args):
    global regs, mem
    if len(args) == 1:
        data_length = _get_data_length(args[0])
        if data_length != 8:
            val = _get_sym_val()
            _write_reg("rdx", val)
        val = _get_sym_val()
        _write_reg("rax", val)
    elif len(args) == 2:
        data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
        src = _get_arg(args[1])
        dst = _get_arg(args[0])
        if _is_ptr(src):
            src_address = _get_address(src)
            val = _read_reg(dst, data_length) * _read_mem(src_address, data_length)
            _write_reg(dst, val)
        elif _is_literal(src):
            val = _read_reg(dst, data_length) * int(src, 16)
            _write_reg(dst, val)
        else:
            val = _read_reg(dst, data_length) * _read_reg(src, data_length)
            _write_reg(dst, val)
    elif len(args) == 3:
        data_length = min(_get_data_length(args[0]), _get_data_length(args[1]), _get_data_length(args[2]))
        src1 = _get_arg(args[1])
        src2 = _get_arg(args[2])
        dst = _get_arg(args[0])
        if _is_ptr(src):
            src_address = _get_address(src1, data_length)
            val = _read_mem(src1_address, data_length) * int(src2, 16)
            _write_reg(dst, val)
        else:
            val = _read_reg(src1, data_length) * int(src2, 16)
            _write_reg(dst, val)


def sar(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    shift_val = int(src, 16)
    val = _read_reg(dst, data_length) / 2 ** shift_val
    _write_reg(dst, val)



def sal(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    shift_val = int(src, 16)
    val = _read_reg(dst, data_length) * 2 ** shift_val
    _write_reg(dst, val)


def shr(args):
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    shift_val = int(src, 16)
    val = _read_reg(dst, data_length)
    try:
        val = int(val)
    except:
        pass
    if type(val) == int:
        val = logical_rshift(val, shift_val)
    else:
        val = _get_sym_val()
    _write_reg(dst, val)


def shl(args):
    sal(args)


def setz(args):
    global regs, mem
    dst = _get_arg(args[0])
    val = _get_sym_val()
    _write_reg(dst, val)


def movsxd(args):
    global regs, mem
    src_data_length = _get_data_length(args[1])
    dst_data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, src_data_length)
        if src_data_length != 64:
            val = _get_sym_val()
        _write_reg(dst, val)
    else:
        val = _get_sym_val()
        _write_reg(dst, val)
    


def movzx(args):
    global regs, mem
    src_data_length = _get_data_length(args[1])
    dst_data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, src_data_length)
        if src_data_length != 64:
            val = _get_sym_val()
        _write_reg(dst, val)
    else:
        val = _get_sym_val()
        _write_reg(dst, val)


def cmp(args):
    global regs, mem
    src_data_length = _get_data_length(args[1])
    dst_data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, src_data_length)
    elif _is_ptr(dst):
        dst_address = _get_address(dst)
        val = _read_mem(dst_address, dst_data_length)
        

def cdqe(args):
    global regs, mem
    dst = "rax"
    val = _get_sym_val()
    _write_reg(dst, val)


def default(_):
    raise Exception("Not Implemented Instruction")


#### Instruction Implementations End   ####


