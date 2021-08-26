import gdb

handled = {}

class Dw_Syscall(gdb.Command):
    message = "syscall relocated to "   
    def __init__(self):
        super(Dw_Syscall, self).__init__("handle_syscall", gdb.COMMAND_DATA)

    def invoke(self, args, from_tty):
        returned = gdb.execute("patch dw *(&memory_access) "+ args, to_string = True)
        #print(returned)
        msg_index = returned.find(self.message)
        str_address = returned[msg_index+len(self.message):].split('\n')[0]
        address = int(str_address,16)
        # print(hex(address))
        handled[address]=1
        gdb.execute('c')

class Dw_metaSC_stat(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_stat, self).__init__("handle_stat", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 4\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_stat\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall stat hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=4 \n\
                            handle_syscall 1610612771\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall stat already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_fstat(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_fstat, self).__init__("handle_fstat", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 5\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_fstat\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall fstat hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=5 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall fstat already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_newfstatat(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_newfstatat, self).__init__("handle_newfstatat", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 262\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_newfstatat\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall newfstatat hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=262 \n\
                            handle_syscall 1610612819\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall newfstatat already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_getdents(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_getdents, self).__init__("handle_getdents", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 141\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_getdents\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall getdents hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=78 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall getdents already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_openat(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_openat, self).__init__("handle_openat", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 322\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_openat\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall openat hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=257 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall openat already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_ioctl(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_ioctl, self).__init__("handle_ioctl", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 29\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_ioctl\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall ioctl hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=16 \n\
                            handle_syscall 536870917\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall ioctl already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_open(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_open, self).__init__("handle_open", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 2\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_open\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall open hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=2 \n\
                            handle_syscall 536870914\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall open already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_fstatfs(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_fstatfs, self).__init__("handle_fstatfs", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 138\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_fstatfs\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall fstatfs hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=138 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall fstatfs already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_brk(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_brk, self).__init__("handle_brk", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 12\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_brk\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall brk hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=12 \n\
                            handle_syscall 536870914\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall brk already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_write(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_write, self).__init__("handle_write", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 1\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_write\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall write hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=1 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall write already handled")
            gdb.execute("set $handle_sys_return=0")

class Dw_metaSC_read(gdb.Command):
    def __init__(self):
        super(Dw_metaSC_read, self).__init__("handle_read", gdb.COMMAND_DATA)
        gdb.execute(
            "catch syscall 0\n\
            commands\n\
                silent\n\
                if ($rax!=-14)\n\
                    continue\n\
                end\n\
                handle_read\n\
                if($handle_sys_return>0)\n\
                    jump *($pc -2)\n\
                end\n\
                if($handle_sys_return==0)\n\
                    c\n\
                end\n\
            end")
        
    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        address = frame.pc() - 2
        print("syscall read hit")
        if(address not in handled):
            gdb.execute("tb *($pc -2)\n\
                        commands\n\
                            silent\n\
                            set $rax=0 \n\
                            handle_syscall 536870915\n\
                        end")
            gdb.execute("set $handle_sys_return=1")
        else:
            print("syscall read already handled")
            gdb.execute("set $handle_sys_return=0")

Dw_Syscall()
Dw_metaSC_stat()
Dw_metaSC_fstat()
Dw_metaSC_newfstatat()
Dw_metaSC_getdents()
Dw_metaSC_openat()
Dw_metaSC_ioctl()
Dw_metaSC_open()
Dw_metaSC_fstatfs()
Dw_metaSC_brk()
Dw_metaSC_write()
Dw_metaSC_read()
