# Script to analyze a sequence of memory address using a simple 1 level, set associative LRU cache.
# $1: Input trace of memory addresses
# $2: Output file, with each memory access tagged as a hit or a miss

import re
import sys
import subprocess
import string
import os

ip_file = sys.argv[1]  # Symbolic address trace
op_file = sys.argv[2]  # Classified address trace
common_file = sys.argv[3]  # File with common cache contents
cache_size = 32768
cache_block_size = 64
set_associativity = 8
set_size = cache_block_size*set_associativity
num_sets = cache_size//set_size  # Integer division
cache_contents = [[] for _ in range(num_sets)]
cache_ages = [[] for _ in range(num_sets)]

# Assuming replacement policy is LRU

symbol_re = re.compile("Irrelevant to Trace")
symbol2_re = re.compile("Non-memory instruction")


#### Find worst alignement of symbolic cache blocks ####
f = open(ip_file, "r")
ip_file_content = f.readlines()
f.close()
symbolic_memory_addresses = {}
for line in ip_file_content:
    text = line.rstrip()
    if("SYMBOLIC" in text):
        tmp = text.split(' ')
        sym = tmp[0]
        alignment = int(tmp[1])
        offset = int(tmp[2])
        if((sym, alignment) not in symbolic_memory_addresses.keys()):
            symbolic_memory_addresses[(sym, alignment)] = []
        symbolic_memory_addresses[(sym, alignment)].append(offset)
symbolic_cache_blocks = []
for s in symbolic_memory_addresses.keys():
    best = (0, [])
    furthest_address = max(symbolic_memory_addresses[s])
    for i in range(s[1] - cache_block_size, 1, s[1]):
        tmp = [(i, i + cache_block_size, 0)]
        while(tmp[-1][1] < furthest_address):
            tmp.append((tmp[-1][0] + cache_block_size, tmp[-1][1] + cache_block_size, (tmp[-1][2] + 1) % cache_block_size))
        if all(any(map(lambda x: y in range(x[0], x[1]), tmp)) for y in symbolic_memory_addresses[s]):
            miss_count = [any(map(lambda x: x in range(y[0], y[1]), symbolic_memory_addresses[s])) for y in tmp].count(True)
            if(best[0] < miss_count):
                best = (miss_count, tmp)
    for bnds in best[1]:
        symbolic_cache_blocks.append((s, bnds))
########################################################


def main():
    global cache_contents
    global cache_ages
    common_lines = []
    with open(common_file) as common:
        for block in common:
            block = block.strip()
            # In this scope we treat all block numbers as integers
            try:
                common_lines.append(int(block, 16))
            except:
                tmp = block.split(' ')
                sym = tmp[0]
                lower = int(tmp[1])
                upper = int(tmp[2])
                for s in symbolic_cache_blocks:
                    if sym == s[0][0] and lower == s[1][0] and upper == s[1][1]:
                        common_lines.append(s)
                        break
    with open(ip_file) as f:
        with open(op_file, "w") as output:
            for line in f:
                text = line.rstrip()
                m1 = symbol_re.match(text)
                m2 = symbol2_re.match(text)
                if(m1):
                    age_cache_contents()
                    output.write(text+"\n")
                elif(m2):
                    output.write(text+"\n")
                elif("SYMBOLIC" in text):
                    tmp = text.split()
                    sym = tmp[0]
                    alignment = int(tmp[1])
                    offset = int(tmp[2])
                    used_symbolic_cache_block = None
                    for s in symbolic_cache_blocks:
                        if sym == s[0][0] and alignment == s[0][1] and offset in range(s[1][0], s[1][1]):
                            used_symbolic_cache_block = s
                            break
                    hit = True
                    if used_symbolic_cache_block:
                        for set_no in range(len(cache_contents)):
                            flag = True
                            if used_symbolic_cache_block not in cache_contents[set_no] and used_symbolic_cache_block in common_lines:
                                flag = not any(type(i) == tuple and i[0] == used_symbolic_cache_block[0] and
                                        i[1][2] != used_symbolic_cache_block[1][2] for i in cache_contents[set_no])
                                cache_contents[set_no].append(used_symbolic_cache_block)
                                cache_ages[set_no].append(None)
                            elif used_symbolic_cache_block in cache_contents[set_no]:
                                index = cache_contents[set_no].index(used_symbolic_cache_block)
                                if cache_ages[set_no][index] >= set_associativity:
                                    hit = False
                            else:
                                flag = not any(type(i) == tuple and i[0] == used_symbolic_cache_block[0] and
                                        i[1][2] != used_symbolic_cache_block[1][2] for i in cache_contents[set_no])
                                cache_contents[set_no].append(used_symbolic_cache_block)
                                cache_ages[set_no].append(None)
                                hit = False
                            update_ages(used_symbolic_cache_block, set_no, flag)
                    if hit:
                        output.write("Hit\n")
                    else:
                        output.write("Miss\n")
                else:
                    addr = int(text, 16)
                    block_no = addr//cache_block_size  # Integer division
                    set_no = block_no % num_sets
                    if block_no not in cache_contents[set_no] and block_no in common_lines:
                        cache_contents[set_no].append(block_no)
                        cache_ages[set_no].append(None)
                        output.write("Hit\n")
                    elif (block_no in cache_contents[set_no]):
                        index = cache_contents[set_no].index(block_no)
                        if cache_ages[set_no][index] < set_associativity:
                            output.write("Hit\n")
                        else:
                            output.write("Miss\n")
                    else:
                        cache_contents[set_no].append(block_no)
                        cache_ages[set_no].append(None)
                        output.write("Miss\n")
                    update_ages(block_no, set_no)


def age_cache_contents():
    global cache_contents
    global cache_ages
    for x in range(len(cache_ages)):
        for y in range(len(cache_ages[x])):
            # cache_ages[x][y]=set_associativity+1 # Clear cache
            cache_ages[x][y] = cache_ages[x][y]  # Don't clear cache.


def update_ages(block_num, set_num, is_first_symbolic_or_concrete=True):
    global cache_contents
    global cache_ages
    index = cache_contents[set_num].index(block_num)
    age = cache_ages[set_num][index]
    if (age == None):
        # This is for a new block, since all existing blocks must be aged
        age = set_associativity+1
    if(not is_first_symbolic_or_concrete):
        youngest_symbolic_cache_block_age = set_associativity + 1
        for x in range(len(cache_ages[set_num])):
            if(type(cache_contents[set_num][x]) == tuple and
                    cache_contents[set_num][x][0] == block_num[0] and
                    cache_contents[set_num][x][1][2] != block_num[1][2] and
                    youngest_symbolic_cache_block_age > cache_ages[set_num][x]):
                youngest_symbolic_cache_block_age = cache_ages[set_num][x]
    for x in range(len(cache_ages[set_num])):
        if(x == index):
            cache_ages[set_num][x] = 0
        elif(is_first_symbolic_or_concrete and 
                cache_ages[set_num][x] <= age):
            cache_ages[set_num][x] += 1
        elif(not is_first_symbolic_or_concrete and
                cache_ages[set_num][x] < youngest_symbolic_cache_block_age):
            cache_ages[set_num][x] += 1


if __name__ == "__main__":
    main()

