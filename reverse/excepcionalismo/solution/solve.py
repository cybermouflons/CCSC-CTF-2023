from z3 import *

import string

TOTAL_ITEMS = 32

u16 = lambda x, y: Concat(x[y + 1], x[y])
u32 = lambda x, y: Concat(x[y + 3], x[y + 2], x[y + 1], x[y])
u64 = lambda x, y: Concat(x[y + 7], x[y + 6], x[y + 5], x[y + 4], x[y + 3], x[y + 2], x[y + 1], x[y])


is_numeric = lambda y: And(y >= ord('0'), y <= ord('9'))
is_alpha_upper = lambda y: And(y >= ord('A'), y <= ord('Z'))
is_alpha_lower = lambda y: And(y >= ord('a'), y <= ord('z'))

solver = Solver()

x = [ BitVec(f'x[{ix}]',  8) for ix in range(TOTAL_ITEMS) ]

# constraint #1: alphanumeric characters
solver.add(
    [ Or(is_alpha_lower(x_i), Or(is_alpha_upper(x_i), is_numeric(x_i))) for x_i in x]
)


# constraint #2: 
solver.add(
    x[0] == ord("C"),
    x[6] == ord("H"),
    x[8] == ord("2"),
    x[10] == ord("h"),
    x[17] == ord("o"),
    x[28] == ord("e"),
)


even = 0
for i in range(0, 32, 2):
    even += ZeroExt(8, x[i])

odd = 0
for i in range(1, 32, 2):
    odd += ZeroExt(8, x[i])

total = even + odd

# consrtaint #3:
solver.add(
    total == BitVecVal(2803, 16),
    even == BitVecVal(1403, 16),
    odd == BitVecVal(1400, 16)
)

# consrtaint #4:
solver.add(
    ZeroExt(56, x[3]) +\
    ZeroExt(48, u16(x, 6)) +\
    ZeroExt(32, u32(x, 12)) +\
    u64(x, 24) == BitVecVal(3847032193106119999, 64)
)

# consrtaint #5:
solver.add(
    ZeroExt(8, x[19]) * ZeroExt(8, x[22]) == BitVecVal(10920, 16),
    ZeroExt(8, x[28]) * ZeroExt(8, x[29]) == BitVecVal(10403, 16),
    ZeroExt(8, x[14]) * ZeroExt(8, x[5])  == BitVecVal(2652, 16),
    ZeroExt(8, x[13]) * ZeroExt(8, x[21]) == BitVecVal(87 * 75, 16),
)

# consrtaint #6:
solver.add(
    x[9] - x[8] == BitVecVal(21, 8),
)

# consrtaint #7:
solver.add(
    ZeroExt(56, x[0]) +\
    ZeroExt(48, u16(x, 12)) +\
    ZeroExt(32, u32(x, 14)) +\
    u64(x, 20) == BitVecVal(3990552343616493840, 64),
    
    ZeroExt(56, x[0]) +\
    ZeroExt(48, u16(x, 0)) +\
    ZeroExt(32, u32(x, 0)) +\
    u64(x, 0) == BitVecVal(7730486428687202060, 64)
)

solutions = {}

while solver.check() == sat:
    model = solver.model()
    result = [model[x[i]].as_long() for i in range(TOTAL_ITEMS)]
    result = ''.join(chr(c) for c in result)

    if solutions.get(result, None):
        break
    
    solutions[result] = True
    
else:
    print('No solution found.')
    exit()

print(solutions.keys())
# CRpyr4Hk2GhxHW3vsolhRKiC6Ja7egc5