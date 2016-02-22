import angr
import claripy
import simuvex
import logging

logging.getLogger('angr.path_group').setLevel(logging.DEBUG)

# Setup the binary project
password_filename = '.password'
p = angr.Project('./filechecker', load_options={"auto_load_libs":False})

# We begin analysis from the entry point of the binary
state = p.factory.entry_state()

# Taken from reversing the binary - taken from radare2
"""
=--------------------------------=
|  0x4006ca                      |
| mov dword [rbp-local_2_4], 0xf | <--- Password length counter
| mov dword [rbp - 4], 0         |
| mov dword [rbp-local_1], 0     |
| jmp 0x400724 ;[e]              |
=--------------------------------=
"""
password_len = 0xf

# Create our symbolic input for our symbolic memory region
s_password = state.se.BVS('password_bytes', password_len * 8)
    
# Create our symbolic memory region for our symbolic file
content = simuvex.SimSymbolicMemory(memory_id='file_{}'.format(password_filename))
content.set_state(state)
content.store(0, s_password)

# Associate our symbolic file with the correct file name
password_file = simuvex.SimFile(password_filename, 'rw', size=15, content=content)
fs = {
    password_filename: password_file
}
state.posix.fs = fs

# Explore until the "Congrats" message and avoid all other messages
pg = p.factory.path_group(state)
pg.explore(find=0x400743, avoid=(0x400683, 0x4006b6, 0x400732))

state = pg.found[0].state

# Grab current files from our files dict
files = state.posix.files

# The largest file ID is the content of the file we care about
"""
{0: <simuvex.storage.file.SimFile object at 0x7ffff0aa1410>, 1: <simuvex.storage.file.SimFile object at 0x7ffff0aa1690>, 2: <simuvex.storage.file.SimFile object at 0x7ffff0aa1910>, 3: <simuvex.storage.file.SimFile object at 0x7ffff5694960>, 4: <simuvex.storage.file.SimFile object at 0x7ffff5694960>, 3221227200L: <simuvex.storage.file.SimFile object at 0x7ffff089f5f0>}
"""
curr_file_id = max(files.keys())

print("[+] Solving for file content.. patience young grasshoppa..")
# Print contents of our file
print(state.posix.dumps(curr_file_id))
