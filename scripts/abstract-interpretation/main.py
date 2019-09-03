#!/usr/bin/env python

import sys
import string

from parser import Parser
from instruction import Ins
from exec_state import ExecutionState
from exec_engine import ExecutionEngine 

ip_file = sys.argv[1]

def main():
  
  ins_list = Parser.parse(ip_file)
  print ins_list[0].IP
  print ins_list[0].regs
  print ins_list[0].category
  print ins_list[0].opcode
  print ins_list[0].disass
  print ins_list[0].addresses
  #init_state = ExecutionState(ins_list[0].regs, {})   #For some reason initial state is integers
  #engine = ExecutionEngine(init_state)
  #engine.execute_instruction(ins_list[0])
  #print engine.state.regs
  #print engine.state.mem

if __name__ == '__main__':
    main()

