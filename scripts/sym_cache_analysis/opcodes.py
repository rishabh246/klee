import sympy
import sympy.parsing.sympy_parser
#import inspect


mem  = {}# Memory
regs = {}# Registers
sym_cntr = 0# Counter for new symbolic variables
touched_locs = []# List of touched memory locations


real_reg_vals = []# Ordered list of real values of registers after each instruction
real_reg_vals_cntr = 1# Counter for checking the register values in each step


def check(opcode, args, reg):
    """
        Checks the obtained values of registers against the real values.
        Used for debugging. Call it after executing each instruction.
    """
    global real_reg_vals_cntr
    if real_reg_vals_cntr == len(real_reg_vals):
        return
    if regs[reg] != real_reg_vals[real_reg_vals_cntr][reg]:
        print opcode, args, reg, regs[reg], real_reg_vals[real_reg_vals_cntr][reg]
    real_reg_vals_cntr += 1
    return

def print_touched_locs():
    """
        Prints unique touched memory locations.
        Renames offset values for the sake of presentation.
    """
    global touched_locs
    print len(touched_locs)
    touched_locs = list(set(touched_locs))
    offset_cntr = 0
    offsets = {}
    # This loop renames offset values.
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
    """
        Initializes registers and memory. Registers are initially
        loaded with the initial values from the trace file.
    """
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
    sym_cntr = 0
    mem.clear()


def parse(ip_file):
    """
        Parses trace file and returns instructions as a list. Also, saves
        the real values of registers in the real_reg_vals for debugging.
    """
    ins_list = []
    ctr = 0
    instruction_info_size = 18
    is_first = True
    with open(ip_file) as trace_file:
        t = {}
        for line in trace_file:
            text = line.rstrip()
            if(" = " in text):
                text = text.split(" = ")
                reg = text[0]
                val = text[1]
                if is_first:
                    val = int(val)
                else:
                    val = int(val, 16)
                t[reg] = val
            elif("|" in text):
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
    """
        Returns a new symbolic variable.
    """
    global sym_cntr
    val = sympy.Symbol("sym_" + str(sym_cntr))
    sym_cntr += 1
    return val


def _get_data_length(arg):
    """
        Returns the required data length of the register or memory reference.
    """
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
    elif (arg in ["r14b", "r9b", "cl", "sil",
                "r10b", "bl", "spl", "r11b",
                "r8b", "dl", "bpl", "r15b",
                "r12b", "dil", "al", "r13b"] or "byte" in arg):
        return 8
    return 64


def _is_ptr(x):
    """
        Checks if the arguments is a pointer.
    """
    if "ptr" in x:
        return True
    return False


def _is_literal(x):
    """
        Checks if the arguments is a literal.
    """
    if "0x" in x:
        return True
    return False


def _get_arg(x):
    """
        Returns the name of the 64-bits register.
        Ex: _get_arg(ax) returns rax.
    """
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
    """
        Writes data to the given address in memory.
    """
    global mem
    _touched_locs_append(address)
    mem[address] = val


def _write_reg(reg, val):
    """
        Writes data to the given register.
    """
    global regs
    regs[reg] = val


def _read_mem(address, data_length=64):
    """
        Returns data in the given address with the given data length.
        If the address is referenced before (which means mem[address]
        has a value), then the value of in the address is returned. If
        it is the first time that this address is referenced, then a new
        symbolic variable is set to the given memory address. If the data
        length is 64, then the value is return directly. However, if it
        is less than 64, then value modulo 2 ^ data length is returned.
    """
    global mem
    _touched_locs_append(address)
    if address not in mem.keys():
        val = _get_sym_val()
        mem[address] = val
    if data_length == 64:
        return mem[address]
    return mem[address] % 2**data_length


def _read_reg(reg, data_length=64):  
    """
        Returns data of the given register with the given data length. If
        the data length is 64, then the value is return directly. However,
        if it is less than 64, then value modulo 2 ^ data length is returned.
    """
    if data_length == 64:
        return regs[reg]
    return regs[reg] % 2**data_length


def _touched_locs_append(address):
    """
        Appends a new address to the touched_locs. Since this function
        is the only point from where a new address can be appended to the
        touched_locs list, it is useful for debugging.
    """
    global touched_locs
    touched_locs.append(address)


def _get_address(x):
    """
        Returns the address indicated by the expression.
        Ex: _get_address("ptr [rdi+rsi*8]") returns some
        number of an expression of symbolic variables.
    """
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
                      "r12", "rdi", "rax", "r13", "rip"]):
                acc *= _read_reg(j, 64)
            elif (j in ["r14d", "r9d", "ecx", "esi",
                        "r10d", "ebx", "esp", "r11d",
                        "r8d", "edx", "ebp", "r15d",
                        "r12d", "edi", "eax", "r13d", "eip"]):
                acc *= _read_reg(j, 32)
            elif (j in ["r14w", "r9w", "cx", "si",
                        "r10w", "bx", "sp", "r11w",
                        "r8w", "dx", "bp", "r15w",
                        "r12w", "di", "ax", "r13w", "ip"]):
                acc *= _read_reg(j, 16)
            elif (j in ["r14b", "r9b", "cb", "sil",
                        "r10b", "bl", "spl", "r11b",
                        "r8b", "dl", "bpl", "r15b",
                        "r12b", "dil", "al", "r13b", "ipl"]):
                acc *= _read_reg(j, 8)
            else:
                acc *= int(j, 16)
            acc *= sign
        address += acc
    return address


#### Helper Functions End   ####


#### Instruction Implementations Start ####


def push(args):
    """
        push instruction.
    """
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
    return


def pop(args):
    """
        pop instruction.
    """
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
    return


def mov(args):
    """
        mov instruction.
    """
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
    return
            

def lea(args):
    """
        lea instruction.
    """
    global regs, mem
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    src_address = _get_address(src)
    _write_reg(dst, src_address)
    return


def add(args):
    """
        add instruction.
    """
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
    return


def sub(args):
    """
        sub instruction.
    """
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
    return


def inc(args):
    """
        inc instruction.
    """
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
    return


def dec(args):
    """
        inc instruction.
    """
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
    return


def call(args):
    """
        call instruction. Does same thing as push.
    """
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
    return


def ret(args):
    """
        call instruction. Similar to pop.
    """
    global regs, mem
    src_address = _read_reg("rsp", 64)
    _read_mem(src_address, 64)
    val = _read_reg("rsp", 64) + 8
    _write_reg("rsp", val)
    return


def xor(args):
    """
        xor instruction. 
    """
    global regs, mem
    data_length = min(_get_data_length(args[0]), _get_data_length(args[1]))
    ## Symbolic xor function implementation starts ##
    class XOR(sympy.Function):
        nargs = (2,)
        @classmethod
        # Below part, somehow, implements Commutativity of xor.
        def eval(cls, arg1, arg2):
            if str(arg1)>str(arg2):
                return XOR(arg2,arg1)
    ## Symbolic xor function implementation ends   ##
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
                # Identity
                if operand1 == 0:
                    val = operand2
                else:
                    val = XOR(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    # Identity
                    if operand2 == 0:
                        val = operand1
                    else:
                        val = XOR(operand1, operand2)
                except:
                    # Self-inverse
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
                # Identity
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
                # Identity
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
                    # Identity
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = XOR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        # Identity
                        if operand2 == 0:
                            val = operand1
                        else:
                            val = XOR(operand1, operand2)
                    except:
                        # Self-inverse
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
                        # Self-inverse
                        if operand1 == operand2:
                            val = 0
                        else:
                            val = XOR(operand1, operand2)
            _write_reg(dst, val)
    return


def and_ins(args):
    """
        and instruction.
        Since "and" is a keyword in Python, name of this function is "and_ins".
    """
    global regs, mem
    ## Symbolic and function implementation starts ##
    class AND(sympy.Function):
        nargs = (2,)
        @classmethod
        # Below part, somehow, implements Commutativity of and.
        def eval(cls, arg1, arg2):
            if str(arg1)>str(arg2):
                return AND(arg2,arg1)
    ## Symbolic and function implementation ends   ##
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
                # Annihilator for and
                if operand1 == 0:
                    val = 0
                else:
                    val = AND(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    # Annihilator for and
                    if operand2 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    # Idempotence of and
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
                # Annihilator for and
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
                # Annihilator for and
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
                    # Annihilator for and
                    if operand1 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        # Annihilator for and
                        if operand2 == 0:
                            val = 0
                        else:
                            val = AND(operand1, operand2)
                    except:
                        # Idempotence of and
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
                    # Annihilator for and
                    if operand1 == 0:
                        val = 0
                    else:
                        val = AND(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        # Annihilator for and
                        if operand2 == 0:
                            val = 0
                        else:
                            val = AND(operand1, operand2)
                    except:
                        # Idempotence of and
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = AND(operand1, operand2)
            _write_reg(dst, val)
    return


def or_ins(args):
    """
        or instruction.
        Since "or" is a keyword in Python, name of this function is "or_ins".
    """
    global regs, mem
    ## Symbolic and function implementation starts ##
    class OR(sympy.Function):
        nargs = (2,)
        @classmethod
        # Below part, somehow, implements Commutativity of or.
        def eval(cls, arg1, arg2):
            if str(arg1)>str(arg2):
                return OR(arg2,arg1)
    ## Symbolic and function implementation ends   ##
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
                # Identity for or
                if operand1 == 0:
                    val = operand2
                else:
                    val = OR(operand1, operand2)
            except:
                try:
                    operand2 = int(operand2)
                    # Identity for or
                    if operand2 == 0:
                        val = operand1
                    else:
                       val = OR(operand1, operand2)
                except:
                    # Idempotence of or
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
                # Identity for or
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
                # Identity for or
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
                    # Identity for or
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = OR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        # Identity for or
                        if operand2 == 0:
                            val = operand1
                        else:
                           val = OR(operand1, operand2)
                    except:
                        # Idempotence of or
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
                    # Identity for or
                    if operand1 == 0:
                        val = operand2
                    else:
                        val = OR(operand1, operand2)
                except:
                    try:
                        operand2 = int(operand2)
                        # Identity for or
                        if operand2 == 0:
                            val = operand1
                        else:
                           val = OR(operand1, operand2)
                    except:
                        # Idempotence of or
                        if operand1 == operand2:
                            val = operand1
                        else:
                            val = OR(operand1, operand2)
            _write_reg(dst, val)
    return


def not_ins(args):
    """
        not instruction.
        Since "not" is a keyword in Python, name of this function is "not_ins".
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    # Symbolic function definition.
    NOT = sympy.Function("NOT")
    dst = _get_arg(args[0])
    if _is_ptr(src):
        dst_address = _get_address(dst)
        operand = _read_mem(dst_address, data_length)
        try:
            operand = int(operand)
            val = ~operand
        except:
            val = NOT(operand)
        _write_reg(dst, val)
    else:
        operand = _read_reg(dst, data_length)
        try:
            operand = int(operand)
            val = ~operand
        except:
            val = NOT(operand)
        _write_reg(dst, val)
    return


def neg(args):
    """
        neg instruction.
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    dst = _get_arg(args[0])
    if _is_ptr(dst):
        dst_address = _get_address(dst)
        val = -_read_mem(dst_address, data_length)
        _write_reg(dst, val)
    else:
        val = -_read_reg(dst, data_length)
        _write_reg(dst, val)
    return


def imul(args):
    """
        imul instruction.
        Since it is signed multiplication, values multiplied directly.

    """
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
    return


def mul(args):
    """
        mul instruction.
        Since it is unsigned multiplication, we cannot simply predict
        the resulting value. Therefore, new symbolic variables are
        created and assigned to the registers as results.
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[0])
    dst = "rax"
    if _is_ptr(src):
        src_address = _get_address(src)
        _read_mem(src_address, data_length)
        if data_length != 8:
            val = _get_sym_val()
            _write_reg("rdx", val)
        val = _get_sym_val()
        _write_reg("rax", val)
    else:
        if data_length != 8:
            val = _get_sym_val()
            _write_reg("rdx", val)
        val = _get_sym_val()
        _write_reg("rax", val)
    return


def sar(args):
    """
        sar instruction.
        Acts like division.
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    shift_val = int(src, 16)
    val = _read_reg(dst, data_length) / 2 ** shift_val
    _write_reg(dst, val)
    return


def sal(args):
    """
        sal instruction.
        Acts like multiplication.
    """
    global regs, mem
    src_data_length = _get_data_length(args[1])
    dst_data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_literal(src):
        shift_val = int(src, 16)
    else:
        shift_val = _read_reg(src, src_data_length)
    val = _read_reg(dst, dst_data_length) * 2 ** shift_val
    _write_reg(dst, val)
    return


def shr(args):
    """
        shr instruction.
    """
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
        val = (val >> shift_val) & (0x7fffffff >> (shift_val - 1))
    else:
        val = _get_sym_val()
    _write_reg(dst, val)
    return


def shl(args):
    """
        shl instruction.
        Acts like division.
    """
    global regs, mem
    src_data_length = _get_data_length(args[1])
    dst_data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_literal(src):
        shift_val = int(src, 16)
    else:
        shift_val = _read_reg(src, src_data_length)
    val = _read_reg(dst, dst_data_length) * 2 ** shift_val
    _write_reg(dst, val)
    return


def setz(args):
    """
        setz instruction.
        Since we cannot simply find the result, result
        is set to be a new symbolic variable.
    """
    global regs, mem
    dst = _get_arg(args[0])
    val = _get_sym_val()
    _write_reg(dst, val)
    return


def setnz(args):
    """
        setnz instruction.
        Since we cannot simply find the result, result
        is set to be a new symbolic variable.
    """
    global regs, mem
    dst = _get_arg(args[0])
    val = _get_sym_val()
    _write_reg(dst, val)
    return


def movsxd(args):
    """
        movsxd instruction.
        Since if the data length is less than 64 but, we cannot simply find the results,
        result is set to be a new symbolic variable. If the data length is 64 bit,
        then it is a simple mov.
    """
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
    return


def movsx(args):
    """
        movsx instruction.
        Since if the data length is less than 64 but, we cannot simply find the results,
        result is set to be a new symbolic variable. If the data length is 64 bit,
        then it is a simple mov.
    """
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
    return
    


def movzx(args):
    """
        movzx instruction.
        Since if the data length is less than 64 but, we cannot simply find the results,
        result is set to be a new symbolic variable. If the data length is 64 bit,
        then it is a simple mov.
    """
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
    return


def cmp(args):
    """
        cmp instruction.
        This instruction only sets some flags so it is not important for us.
        However, if it touches a memory location, we have to save
        this. That is why _read_mem functions are executed anyway.
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(src):
        src_address = _get_address(src)
        val = _read_mem(src_address, data_length)
    elif _is_ptr(dst):
        dst_address = _get_address(dst)
        val = _read_mem(dst_address, data_length)
    return


def cmpxchg(args):
    """
        cmpxchg instruction.
    """
    global regs, mem
    data_length = _get_data_length(args[0])
    src = _get_arg(args[1])
    dst = _get_arg(args[0])
    if _is_ptr(dst):
        dst_address = _get_address(dst)
        dst_val = _read_mem(dst_address, data_length)
        val_rax = _read_reg("rax", data_length)
        if val_rax == dst_val:
            val = _read_reg(src, data_length)
            _write_mem(dst_address, val)
        else:
            _write_reg("rax", dst_val)
    else:
        dst_val = _read_reg(dst, data_length)
        val_rax = _read_reg("rax", data_length)
        if val_rax == dst_val:
            val = _read_reg(src, data_length)
            _write_reg(dst, val)
        else:
            _write_reg("rax", dst_val)
    return
        

def cdqe(args):
    """
        cdqe instruction.
        Since we cannot simply find the result, result
        is set to be a new symbolic variable.
    """
    global regs, mem
    dst = "rax"
    val = _get_sym_val()
    _write_reg(dst, val)
    return


def default(_):
    """
        If an instruction is not in the dont_care list and not
        implemented in this file as a function, this function
        will be called as default and it will raise an exception.
    """
    raise Exception("Not Implemented Instruction")


#### Instruction Implementations End   ####


