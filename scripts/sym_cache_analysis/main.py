import opcodes
import sys

dont_care = ["test", "nop", "jnle", "jnz", "jz", "jmp"]

def main():
    ip_file = sys.argv[1]
    ins_list = opcodes.parse(ip_file)
    opcodes.init()
    for opcode, args in ins_list:
        if opcode not in dont_care:
            try:
                getattr(opcodes, opcode, opcodes.default)(args)
            except Exception:
                print "Not Implemented Instruction:", opcode, ", ".join(args)
        #opcodes.check(opcode, args, "rax")
    opcodes.print_touched_locs()
    
main()

