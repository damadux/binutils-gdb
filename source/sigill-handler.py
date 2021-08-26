import time
import gdb
from time import sleep

def executeLog(command):
    log = False
    if(log):
        print(command)
    gdb.execute(command, to_string=True)
class SigillHandler(gdb.Command):
    def __init__(self):
        super(SigillHandler, self).__init__("sigill-hdl", gdb.COMMAND_DATA)
        gdb.execute("handle SIGILL ignore")
        gdb.execute("catch signal SIGILL")
        gdb.execute("commands \n \
                    silent \n\
                    set scheduler-locking on \n\
                    sigill-hdl \n\
                    end")
    def invoke(self, args, from_tty):
        signal_addr = gdb.selected_frame().pc()
        executeLog("patch handle 1")
        executeLog("si")
        if(gdb.selected_frame().pc() == signal_addr):
            # If we have not made progress, generally we restored an instruction that generates a SEGFAULT
            # We then call the segfault handler
            executeLog("dataWatch-segfault-noc")
            executeLog("si")

        executeLog("patch handle 2")
        executeLog("set scheduler-locking off")
        executeLog("continue")

SigillHandler()