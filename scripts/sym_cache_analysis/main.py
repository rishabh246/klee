import opcodes
import sys

def main():
    ip_file = sys.argv[1]
    ins_list = opcodes.parse(ip_file)
    opcodes.init()
    for opcode, args in ins_list:
        getattr(opcodes, opcode, opcodes.nop)(args)
        #opcodes.check(opcode, args, "rax")
    opcodes.print_touched_locs()
    
main()

