## Appendix: automating the walkthrough with GDB's Python API

Once I understood the flow, I scripted it so the whole first-call/second-call trace replays in one command (`gdb -q -x gdb_script.py`). This version comes from a later build compiled with Intel CET enabled (GCC's default `-fcf-protection` on recent Ubuntu), so every PLT stub starts with `endbr64` and the jump stubs live in a separate `.plt.sec` section. That is why its offsets (`0x1119`, `0x1050`) differ from the ones above.

```python
import gdb

gdb.execute('file driver')
gdb.execute('set environment LD_LIBRARY_PATH=.')
gdb.execute('break ml_func')
gdb.execute('run')

# Get addresses
ml_util_addr  = int(gdb.parse_and_eval('&ml_util_func'))
base          = ml_util_addr - 0x1119
got_ml_util   = base + 0x4000
plt_sec       = base + 0x1050
plt0          = base + 0x1020

print(f'\nbase            = 0x{base:x}')
print(f'ml_util_func    = 0x{ml_util_addr:x}')
print(f'GOT[ml_util]    = 0x{got_ml_util:x}')
print(f'PLT.sec         = 0x{plt_sec:x}')
print(f'PLT[0]          = 0x{plt0:x}')

def got_val():
    raw = gdb.execute(f'x/gx 0x{got_ml_util:x}', to_string=True)
    return int(raw.split(':')[1].strip(), 16)

print(f'\nGOT[ml_util] before first call = 0x{got_val():x}')
print(f'Points back into PLT?           {hex(got_val()).startswith(hex(plt_sec)[:8])}')

# Step through PLT for first call
gdb.execute(f'break *0x{plt_sec:x}')
gdb.execute('continue')

print('\n--- FIRST CALL: entering PLT.sec ---')
print(gdb.execute('x/3i $rip', to_string=True).strip())

gdb.execute('ni')  # skip endbr64
print('\nSkipped endbr64, now at JMP:')
print(gdb.execute('x/2i $rip', to_string=True).strip())

gdb.execute('stepi')  # execute jmp [got] -> bounces to PLT[n]+6
print('\nAfter JMP [GOT] (bounced back into PLT):')
print(gdb.execute('x/3i $rip', to_string=True).strip())

gdb.execute('stepi')  # skip endbr64 in PLT[n]
gdb.execute('stepi')  # push function_index
print('\nAfter PUSH function_index (0x0):')
print(gdb.execute('x/2i $rip', to_string=True).strip())

gdb.execute('stepi')  # jmp PLT[0]
print('\nJumped to PLT[0] resolver trampoline:')
print(gdb.execute('x/3i $rip', to_string=True).strip())

# Now let ld.so resolver run fully
gdb.execute('delete breakpoints')
gdb.execute(f'break *0x{ml_util_addr:x}')
gdb.execute('continue')
print('\nResolver DONE. Now at ml_util_func entry:')
print(gdb.execute('x/2i $rip', to_string=True).strip())
print(f'\nGOT[ml_util] AFTER resolver = 0x{got_val():x}')
print(f'Equals &ml_util_func?        {got_val() == ml_util_addr}')

# Second call
gdb.execute('delete breakpoints')
gdb.execute('break ml_func')
gdb.execute('continue')  # finish first ml_func, hit second
gdb.execute(f'break *0x{plt_sec:x}')
gdb.execute('continue')  # inside second ml_func, hits PLT.sec

print('\n--- SECOND CALL: entering PLT.sec ---')
print(f'GOT[ml_util] = 0x{got_val():x}  (already resolved)')
gdb.execute('ni')   # skip endbr64
gdb.execute('stepi')  # execute jmp [got]
rip_after = int(gdb.parse_and_eval('$rip'))
print(f'\nAfter JMP [GOT]: RIP = 0x{rip_after:x}')
print(f'ml_util_func address = 0x{ml_util_addr:x}')
print(f'Went directly to ml_util_func? {rip_after == ml_util_addr}')
print('\nNO push, NO resolver, NO PLT[0]. Just one jump.')

gdb.execute('quit')
```
