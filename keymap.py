# keymap.py
# Extracted hardware indices for the AULA S75 Pro matrix.
# Generated from rgb-keyboard.xml (one-time parse; XML not loaded at runtime).
#
# The 80 light_index integers below correspond exactly to the slots the MCU
# expects populated in the 576-byte custom-light table (PROTOCOL.md §5).
# The set is used by set_custom_lighting() to pre-populate each slot's index
# byte (slot[0] = light_index) — matching what FUN_0044b900 in the official
# driver does for every physical key, even those set to off (RGB = 0, 0, 0).
#
# DO NOT add indices that are not in this set: slot 0 is reserved (always
# zero), and indices ≥ 120 approach the AA 55 trailer at offsets 574–575
# (slot 143).  The set acts as an allowlist that keeps set_custom_lighting()
# safe against bad caller input.

# ── Physical indices ────────────────────────────────────────────────────────

PHYSICAL_INDICES: frozenset[int] = frozenset({
    # Row 0 — Function keys
     1,   # Esc
     2,   # F1
     3,   # F2
     4,   # F3
     5,   # F4
     6,   # F5
     7,   # F6
     8,   # F7
     9,   # F8
    10,   # F9
    11,   # F10
    12,   # F11
    13,   # F12

    # Row 1 — Number row
    19,   # ~`
    20,   # !1
    21,   # @2
    22,   # #3
    23,   # $4
    24,   # %5
    25,   # ^6
    26,   # &7
    27,   # *8
    28,   # (9
    29,   # )0
    30,   # _-
    31,   # +=

    # Row 2 — QWERTY top
    37,   # Tab
    38,   # Q
    39,   # W
    40,   # E
    41,   # R
    42,   # T
    43,   # Y
    44,   # U
    45,   # I
    46,   # O
    47,   # P
    48,   # {[
    49,   # }]

    # Row 3 — Home row
    55,   # CapsLock
    56,   # A
    57,   # S
    58,   # D
    59,   # F
    60,   # G
    61,   # H
    62,   # J
    63,   # K
    64,   # L
    65,   # :;
    66,   # "'
    67,   # |\

    # Row 4 — Bottom alpha row
    73,   # Shift_L
    74,   # Z
    75,   # X
    76,   # C
    77,   # V
    78,   # B
    79,   # N
    80,   # M
    81,   # ,<
    82,   # .>
    83,   # /?
    84,   # Shift_R
    85,   # Enter

    # Row 5 — Modifier / spacebar row
    91,   # Ctrl_L
    92,   # Win_L
    93,   # Alt_L
    94,   # Space
    95,   # Alt_R
    96,   # Fn
    98,   # Ctrl_R

    # Navigation cluster
    99,   # ←
   100,   # ↓
   101,   # ↑
   102,   # →
   103,   # Backspace

    # Extra cluster (top-right)
   117,   # Home
   119,   # Del
   120,   # End
})

assert len(PHYSICAL_INDICES) == 80, (
    f"Expected 80 physical indices, got {len(PHYSICAL_INDICES)}"
)

# ── Friendly-name map ───────────────────────────────────────────────────────
# Maps human-readable key names to their light_index integers.
# Use this in CLI commands or scripts for readable key addressing.

KEYMAP: dict[str, int] = {
    # Function row
    "Esc":      1,
    "F1":       2,
    "F2":       3,
    "F3":       4,
    "F4":       5,
    "F5":       6,
    "F6":       7,
    "F7":       8,
    "F8":       9,
    "F9":      10,
    "F10":     11,
    "F11":     12,
    "F12":     13,

    # Number row
    "`":       19,
    "1":       20,
    "2":       21,
    "3":       22,
    "4":       23,
    "5":       24,
    "6":       25,
    "7":       26,
    "8":       27,
    "9":       28,
    "0":       29,
    "-":       30,
    "=":       31,

    # Top alpha row
    "Tab":     37,
    "Q":       38,
    "W":       39,
    "E":       40,
    "R":       41,
    "T":       42,
    "Y":       43,
    "U":       44,
    "I":       45,
    "O":       46,
    "P":       47,
    "[":       48,
    "]":       49,

    # Home row
    "CapsLock": 55,
    "A":        56,
    "S":        57,
    "D":        58,
    "F":        59,
    "G":        60,
    "H":        61,
    "J":        62,
    "K":        63,
    "L":        64,
    ";":        65,
    "'":        66,
    "\\":       67,

    # Bottom alpha row
    "Shift_L":  73,
    "Z":        74,
    "X":        75,
    "C":        76,
    "V":        77,
    "B":        78,
    "N":        79,
    "M":        80,
    ",":        81,
    ".":        82,
    "/":        83,
    "Shift_R":  84,
    "Enter":    85,

    # Modifier / spacebar row
    "Ctrl_L":   91,
    "Win_L":    92,
    "Alt_L":    93,
    "Space":    94,
    "Alt_R":    95,
    "Fn":       96,
    "Ctrl_R":   98,

    # Navigation
    "Left":     99,
    "Down":    100,
    "Up":      101,
    "Right":   102,
    "Backspace": 103,

    # Extra cluster
    "Home":    117,
    "Del":     119,
    "End":     120,
}

assert set(KEYMAP.values()) == PHYSICAL_INDICES, (
    "KEYMAP values must be a 1-to-1 subset of PHYSICAL_INDICES"
)
