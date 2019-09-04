import opcodes
import sys


"""
    Use as follows: python main.py pincounts.log
"""


# List of instructions that are not important.
dont_care = ["test", "nop", "jnle", "jnz",
             "jz", "jmp", "jl", "js",
             "jle", "jbe", "jnbe", "jb",
             "jnb", "jnl", "syscall"]

def main():
    ip_file = sys.argv[1]
    ins_list = opcodes.parse(ip_file)
    opcodes.init()
    for opcode, args in ins_list:
        if opcode not in dont_care:
            try:
                getattr(opcodes, opcode, opcodes.default)(args)
            except Exception("Not Implemented Instruction"):
                print "Not Implemented Instruction:", opcode, ", ".join(args)
        #opcodes.check(opcode, args, "rax")
    opcodes.print_touched_locs()
    

main()


