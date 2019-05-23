from itertools import product

BTN_A = 1 << 7
BTN_B = 1 << 6
BTN_SELECT = 1 << 5
BTN_START = 1 << 4
BTN_UP = 1 << 3
BTN_DOWN = 1 << 2
BTN_LEFT = 1 << 1
BTN_RIGHT = 1

ARROWS = [BTN_UP, BTN_DOWN, BTN_LEFT, BTN_RIGHT]

BUTTONS = [BTN_A, BTN_B, BTN_SELECT, BTN_START]

COMBINATIONS = ARROWS + BUTTONS

key1 = [ 0x70, 0x75, 0x4e, 0x2c, 0x7f, 0xe7, 0x71, 0xe3, 0x60, 0x64, 0x30, 0x13, 0xe9, 0x24, 0xf2, 0x30,
	0x72, 0x12, 0x67, 0x5d, 0x58, 0x96, 0x15, 0xd0, 0x02, 0x54, 0x1e, 0x32, 0x93, 0x51, 0xfb, 0x39]
key2 = [ 0x19, 0x13, 0x0f, 0x0a, 0x06, 0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x05, 0x08, 0x0c, 0x11, 0x16,
	0x1b, 0x20, 0x25, 0x29, 0x2c, 0x2f, 0x31, 0x31, 0x31, 0x30, 0x2e, 0x2b, 0x27, 0x22, 0x1e, 0x19 ]

def is_xdigit(c):
    return c in map(ord, "0123456789abcdef")

def possible_inputs():
    candidates = []
    for i in range(0,0x10):
        c1 = {n for n in COMBINATIONS if is_xdigit(n ^ key1[i] ^ key2[i])}
        c2 = {n for n in COMBINATIONS if is_xdigit(n ^ key1[i+0x10] ^ key2[i+0x10])}
        candidates.append(c1.intersection(c2))

    return candidates

def test_input(input):
    state1 = 0
    state2 = 0

    for i in range(0, 16):
        a = input[i]
        button_state1 = a
        button_state2 = a

        for j in range(8, 0, -1):
            # asl button_state1
            carry = (button_state1 & 0x80) >> 7
            button_state1 = (button_state1 << 1) & 0xff

            # ror a
            tmp = a
            a = (a >> 1) | (carry << 7)
            carry = (tmp & 0x1)

            # and #$80
            a = a & 0x80
            # eor state2
            a = (a ^ state2)

            # asl state1
            carry = (state1 & 0x80) >> 7
            state1 = (state1 << 1) & 0xff

            # rol a
            tmp = a
            a = ((a << 1) | carry) & 0xff
            carry = (tmp & 0x80) >> 7

            # bcc data_c212
            if carry != 0:
                # tay
                y = a
                # lda state1
                a = state1
                # eor #$37
                a = (a ^ 0x37)
                # sta state1
                state1 = a
                # tya
                a = y
                # eor #$13
                a = (a ^ 0x13)
            # sta state2
            state2 = a
        # sta button_state2
        # button_state2 = a

    return state1 == 0x43 and state2 == 0x32

def print_flag(input):
        print([hex(c) for c in input])
        print(f"HITB{{{''.join([chr(input[i%0x10]^key1[i]^key2[i]) for i in range(0,0x20)])}}}")

for input in product(*possible_inputs()):
    if test_input(input):
        print_flag(input)
