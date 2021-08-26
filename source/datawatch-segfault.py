from capstone import *
import gdb
import struct
import binascii
jumppad_threshold = 1
# x86_regs = ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
x86_regs = ["rsp", "rbp", "rdi", "rsi", "rbx", "rdx", "rcx", "rax", "r12", "r13", "r15", "r14", "r11", "r10", "r9", "r8"]
to_64_regs = {'cl': 'rcx', 'edi': 'rdi', 'al': 'rax', 'cx': 'rcx', 'ebp': 'rbp', 'ax': 'rax', 'edx': 'rdx', 'ebx': 'rbx', 'r15d': 'r15', 'r13w': 'r13', 'r15b': 'r15', 'esp': 'rsp', 'spl': 'rsp', 'r8b': 'r8', 'r11d': 'r11', 'r8d': 'r8', 'r13d': 'r13', 'r15w': 'r15', 'r13b': 'r13', 'esi': 'rsi', 'r11w': 'r11', 'dl': 'rdx', 'di': 'rdi', 'bl': 'rbx', 'r8w': 'r8', 'eax': 'rax', 'bp': 'rbp', 'dx': 'rdx', 'bx': 'rbx', 'ecx': 'rcx', 'dil': 'rdi', 'r14d': 'r14', 'r14b': 'r14', 'r12w': 'r12', 'r10b': 'r10', 'r9d': 'r9', 'sp': 'rsp', 'r9b': 'r9', 'bpl': 'rbp', 'r10d': 'r10', 'r14w': 'r14', 'si': 'rsi', 'r12b': 'r12', 'r12d': 'r12', 'r9w': 'r9', 'sil': 'rsi', 'r10w': 'r10', 'r11b': 'r11'}

def debugLog(a):
    debug = False
    if(debug):
        print(a)

def debugLogNoc(a):
    debug = False
    if(debug):
        print(a)

class DataWatch(gdb.Command):
    count = 0

    def __init__(self):
        super(DataWatch, self).__init__("dataWatch-segfault", gdb.COMMAND_DATA)
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        self.count += 1
        debugLog(("count", self.count))

        address = frame.pc()
        inf = gdb.inferiors()[0]
        insn = inf.read_memory(int(address),16)
        insn = struct.unpack(">BBBBBBBBBBBBBBBB", insn)
        debugLog(insn)
        insn = bytearray(insn)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        jmps = ["jmp", "call"]
        read_regs = 0
        # contains : reg, ridx, sca, dis
        for i in md.disasm(insn, address):
            (_, regs_written) = i.regs_access()
            regs_written_extended = []
            for r in regs_written:
                regs_written_extended.append(i.reg_name(r))
                if(i.reg_name(r) in to_64_regs):
                    regs_written_extended.append(to_64_regs[i.reg_name(r)])
            mem_operands = 0
            read_regs = 0
            for op in i.operands:
                if op.type == 3: #X86_OP_MEM there can actually be only one
                    mem_operands += 1
                    reg = op.mem.base
                    ridx = op.mem.index
                    sca = op.mem.scale
                    dis = op.mem.disp
                    debugLog((reg, ridx, sca, dis))
                    idx_reg = x86_regs.index(i.reg_name(reg))
                    # repositionning dis in the right range if negative
                    if(dis < 0):
                        dis +=2**16 
                    if(idx_reg != None):
                        read_regs += 2**(4*(mem_operands-1)) * idx_reg + (2**(12+4*(mem_operands-1)))*dis
                        if(ridx != 0):
                            idx_ridx = x86_regs.index(i.reg_name(ridx))
                            #Watch out for negatives
                            read_regs = idx_reg + (2**4)*idx_ridx + (2**8)*sca + (2**12)*dis + 2**28
                            if ((i.reg_name(ridx) not in regs_written_extended) and (i.mnemonic not in jmps) and ('rsp' not in regs_written_extended)):
                                # Read only registers' value needs to be restored after operation
                                read_regs += (2**31) # no overflowing of uint32                        
                        if ((i.reg_name(reg) not in regs_written_extended) and (i.mnemonic not in jmps) and ('rsp' not in regs_written_extended)):
                            # Read only registers' value needs to be restored after operation
                            read_regs += (2**29) # no overflowing of uint32
                        if(mem_operands==2):
                            read_regs+=2**30
            break # We only look at the first instruction
        debugLog(hex(read_regs))
        if(read_regs == 0):
            print(("No registers read for adress :",hex(address)))
        else:
            #print(hex(address))
            #print(hex(read_regs))
            gdb.execute('patch dw *(&memory_access) '+str(read_regs))
        gdb.execute('set scheduler-locking off')
        gdb.execute("continue")

class DataWatchnoc(gdb.Command):
    count = 0

    def __init__(self):
        super(DataWatchnoc, self).__init__("dataWatch-segfault-noc", gdb.COMMAND_DATA)
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        self.count += 1
        debugLogNoc(("count", self.count))
        address = frame.pc()
        inf = gdb.inferiors()[0]
        insn = inf.read_memory(int(address),16)
        insn = struct.unpack(">BBBBBBBBBBBBBBBB", insn)
        insn = bytearray(insn)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        jmps = ["jmp", "call"]
        read_regs = 0
        # contains : reg, ridx, sca, dis
        for i in md.disasm(insn, address):
            (_, regs_written) = i.regs_access()
            regs_written_extended = []
            for r in regs_written:
                regs_written_extended.append(i.reg_name(r))
                if(i.reg_name(r) in to_64_regs):
                    regs_written_extended.append(to_64_regs[i.reg_name(r)])
            mem_operands = 0
            read_regs = 0
            for op in i.operands:
                if op.type == 3: #X86_OP_MEM there can actually be only one
                    mem_operands += 1
                    reg = op.mem.base
                    ridx = op.mem.index
                    sca = op.mem.scale
                    dis = op.mem.disp
                    debugLogNoc((reg, ridx, sca, dis))
                    idx_reg = x86_regs.index(i.reg_name(reg))
                    debugLogNoc("Index register :")
                    debugLogNoc(idx_reg)
                    # repositionning dis in the right range if negative
                    if(dis < 0):
                        dis +=2**16 
                    if(idx_reg != None):
                        read_regs += 2**(4*(mem_operands-1)) * idx_reg + (2**(12+4*(mem_operands-1)))*dis
                        if(ridx != 0):
                            idx_ridx = x86_regs.index(i.reg_name(ridx))
                            debugLogNoc("Index register :")
                            debugLogNoc(idx_reg)
                            #Watch out for negatives
                            read_regs = idx_reg + (2**4)*idx_ridx + (2**8)*sca + (2**12)*dis + 2**28
                            if ((i.reg_name(ridx) not in regs_written_extended) and (i.mnemonic not in jmps) and ('rsp' not in regs_written_extended)):
                                # Read only registers' value needs to be restored after operation
                                read_regs += (2**31) # no overflowing of uint32                        
                        if ((i.reg_name(reg) not in regs_written_extended) and (i.mnemonic not in jmps) and ('rsp' not in regs_written_extended)):
                            # Read only registers' value needs to be restored after operation
                            read_regs += (2**29) # no overflowing of uint32

                        if(mem_operands==2):
                            read_regs+=2**30
            break # We only look at the first instruction
        debugLogNoc(hex(read_regs))
        if(read_regs == 0):
            print(("No registers read for adress :",hex(address)))
        else:
            gdb.execute('patch dw *(&memory_access) '+str(read_regs))

DataWatch()
DataWatchnoc()

