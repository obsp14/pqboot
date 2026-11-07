# qemu_gdb_skip.py - instruction-skip fault injection on QEMU (UNTESTED).
#
# Emulates a glitch that skips ONE instruction in the TF-A verifier, the
# software analogue of a voltage/clock glitch. Usage:
#
#   1. Start QEMU halted with a GDB stub:   make run-only QEMU_EXTRA_ARGS="-s -S"
#   2. Find the address of a conditional branch after a check, e.g.
#        aarch64-linux-gnu-objdump -d bl2.elf | grep -A3 'pqb_image_verify'
#   3. aarch64-linux-gnu-gdb bl2.elf -x faultinj/qemu_gdb_skip.py \
#        -ex 'pqb_skip 0x0e01c4a8' -ex 'target remote :1234' -ex 'continue'
#
# With an unhardened build (PQB_HARDEN=0) skipping the branch after the
# PQ signature check boots a tampered image; with PQB_HARDEN=1 the second
# check or the flow counter catches it and TF-A panics.
import gdb


class SkipBreakpoint(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(f"*{addr:#x}", internal=False)
        self.hits = 0

    def stop(self):
        self.hits += 1
        pc = int(gdb.parse_and_eval("$pc"))
        gdb.execute(f"set $pc = {pc + 4:#x}")     # AArch64: fixed 4-byte insns
        print(f"[faultinj] skipped instruction at {pc:#x} (hit {self.hits})")
        return False                               # keep running


class PqbSkip(gdb.Command):
    """pqb_skip ADDR - skip the instruction at ADDR every time it executes."""

    def __init__(self):
        super().__init__("pqb_skip", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        SkipBreakpoint(int(arg, 0))


PqbSkip()
