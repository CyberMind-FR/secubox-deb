#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox HID Keyboard — Send keystrokes via USB HID gadget
# Used by TTY mode for automated U-Boot/debug commands
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly HIDG="/dev/hidg0"
readonly NULL='\x00'

# USB HID Keyboard Scan Codes (US layout)
declare -A KEYMAP=(
    ['a']=4  ['b']=5  ['c']=6  ['d']=7  ['e']=8  ['f']=9  ['g']=10 ['h']=11
    ['i']=12 ['j']=13 ['k']=14 ['l']=15 ['m']=16 ['n']=17 ['o']=18 ['p']=19
    ['q']=20 ['r']=21 ['s']=22 ['t']=23 ['u']=24 ['v']=25 ['w']=26 ['x']=27
    ['y']=28 ['z']=29
    ['1']=30 ['2']=31 ['3']=32 ['4']=33 ['5']=34 ['6']=35 ['7']=36 ['8']=37
    ['9']=38 ['0']=39
    [' ']=44 ['-']=45 ['=']=46 ['[']=47 [']']=48 ['\\']=49 [';']=51 ["'"]=52
    ['`']=53 [',']=54 ['.']=55 ['/']=56
)

# Shift-modified keys
declare -A SHIFT_KEYMAP=(
    ['A']=4  ['B']=5  ['C']=6  ['D']=7  ['E']=8  ['F']=9  ['G']=10 ['H']=11
    ['I']=12 ['J']=13 ['K']=14 ['L']=15 ['M']=16 ['N']=17 ['O']=18 ['P']=19
    ['Q']=20 ['R']=21 ['S']=22 ['T']=23 ['U']=24 ['V']=25 ['W']=26 ['X']=27
    ['Y']=28 ['Z']=29
    ['!']=30 ['@']=31 ['#']=32 ['$']=33 ['%']=34 ['^']=35 ['&']=36 ['*']=37
    ['(']=38 [')']=39 ['_']=45 ['+']=46 ['{']=47 ['}']=48 ['|']=49 [':']=51
    ['"']=52 ['~']=53 ['<']=54 ['>']=55 ['?']=56
)

# Special keys
readonly KEY_ENTER=40
readonly KEY_ESC=41
readonly KEY_BACKSPACE=42
readonly KEY_TAB=43
readonly KEY_SPACE=44
readonly KEY_CTRL=0x01   # Left Ctrl modifier
readonly KEY_SHIFT=0x02  # Left Shift modifier
readonly KEY_ALT=0x04    # Left Alt modifier

# Send a single keystroke
# Args: modifier keycode
send_key() {
    local mod=${1:-0}
    local key=${2:-0}

    # HID report: [modifier, reserved, key1, key2, key3, key4, key5, key6]
    printf "\\x%02x\\x00\\x%02x\\x00\\x00\\x00\\x00\\x00" "$mod" "$key" > "$HIDG"

    # Release
    printf "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" > "$HIDG"
}

# Type a string
type_string() {
    local str="$1"
    local delay="${2:-0.05}"

    for ((i=0; i<${#str}; i++)); do
        local char="${str:$i:1}"
        local mod=0
        local keycode=0

        if [[ -n "${KEYMAP[$char]:-}" ]]; then
            keycode=${KEYMAP[$char]}
        elif [[ -n "${SHIFT_KEYMAP[$char]:-}" ]]; then
            keycode=${SHIFT_KEYMAP[$char]}
            mod=$KEY_SHIFT
        else
            # Unknown character, skip
            continue
        fi

        send_key "$mod" "$keycode"
        sleep "$delay"
    done
}

# Send Enter key
send_enter() {
    send_key 0 $KEY_ENTER
}

# Send Ctrl+C
send_ctrl_c() {
    send_key $KEY_CTRL 6  # 'c' = keycode 6
}

# Send a command (type + enter)
send_command() {
    local cmd="$1"
    local delay="${2:-0.03}"

    type_string "$cmd" "$delay"
    sleep 0.1
    send_enter
}

# Process command queue
process_queue() {
    local queue_file="${1:-/run/secubox-cmd-queue}"

    if [[ ! -f "$queue_file" ]]; then
        echo "Queue file not found: $queue_file"
        return 1
    fi

    # Read and process commands from JSON array
    while true; do
        local cmd
        cmd=$(jq -r '.[0] // empty' "$queue_file" 2>/dev/null)

        if [[ -z "$cmd" ]]; then
            break
        fi

        echo "Sending: $cmd"
        send_command "$cmd"

        # Remove processed command from queue
        jq 'del(.[0])' "$queue_file" > "${queue_file}.tmp" && mv "${queue_file}.tmp" "$queue_file"

        sleep 0.5
    done
}

# Interactive mode - read from stdin
interactive_mode() {
    echo "SecuBox HID Keyboard - Interactive Mode"
    echo "Type commands, they will be sent as keystrokes"
    echo "Special: !enter !ctrl-c !esc !delay:N"
    echo "Ctrl+D to exit"
    echo ""

    while IFS= read -r line; do
        case "$line" in
            '!enter')   send_enter ;;
            '!ctrl-c')  send_ctrl_c ;;
            '!esc')     send_key 0 $KEY_ESC ;;
            '!delay:'*) sleep "${line#!delay:}" ;;
            *)          send_command "$line" ;;
        esac
    done
}

# Main
case "${1:-}" in
    type)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 type 'string'"; exit 1; }
        type_string "$2"
        ;;
    cmd|command)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 cmd 'command'"; exit 1; }
        send_command "$2"
        ;;
    enter)
        send_enter
        ;;
    ctrl-c)
        send_ctrl_c
        ;;
    queue)
        process_queue "${2:-/run/secubox-cmd-queue}"
        ;;
    interactive|-i)
        interactive_mode
        ;;
    *)
        echo "SecuBox HID Keyboard — Send keystrokes via USB HID gadget"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  type 'string'     Type a string (no enter)"
        echo "  cmd 'command'     Type command + Enter"
        echo "  enter             Send Enter key"
        echo "  ctrl-c            Send Ctrl+C"
        echo "  queue [file]      Process command queue file"
        echo "  interactive       Interactive mode (stdin)"
        echo ""
        echo "Examples:"
        echo "  $0 cmd 'printenv'"
        echo "  $0 cmd 'setenv bootcmd run bootusb'"
        echo "  $0 type 'hello' && $0 enter"
        echo "  echo 'boot' | $0 interactive"
        exit 1
        ;;
esac
