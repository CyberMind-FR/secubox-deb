/*
 * parser.h - White-grammar CDC command parser for Smart-Strip
 *
 * Strict BNF (see docs/hardware/smart-strip-v1.1.md §6 for full grammar):
 *
 *   <line>    ::= <cmd> "\n"
 *   <cmd>     ::= <set_led> | <set_all> | <anim> | <hbt> | <reset> | <status>
 *   <set_led> ::= "SET_LED" <sp> <idx> <sp> <byte> <sp> <byte> <sp> <byte>
 *   <set_all> ::= "SET_ALL" <sp> <byte> <sp> <byte> <sp> <byte>
 *   <anim>    ::= "ANIM"    <sp> <anim_id>
 *   <hbt>     ::= "HBT"
 *   <reset>   ::= "RESET"
 *   <status>  ::= "STATUS"
 *   <idx>     ::= "0" | "1" | "2" | "3" | "4" | "5"
 *   <byte>    ::= "0".."255" (no leading zeros except "0")
 *   <anim_id> ::= "0".."255"
 *   <sp>      ::= " "
 *
 * Anything not matching: dropped + counter incremented + entry written
 * into the diagnostic ring (timestamp + 8 first bytes for forensics).
 *
 * The parser is a finite state machine, no malloc, no recursion,
 * worst-case bounded execution time, watchdog-friendly.
 *
 * SecuBox / CyberMind - SBX-STR-01 v1.1
 */

#ifndef SBX_PARSER_H
#define SBX_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ring_buffer.h"

#define SBX_LED_COUNT       6u
#define SBX_LINE_MAX        64u   /* longest valid command + LF */
#define SBX_DIAG_RING_SIZE  128u  /* must be power of 2 */

typedef enum {
    SBX_CMD_NONE = 0,
    SBX_CMD_SET_LED,
    SBX_CMD_SET_ALL,
    SBX_CMD_ANIM,
    SBX_CMD_HBT,
    SBX_CMD_RESET,
    SBX_CMD_STATUS,
} sbx_cmd_kind_t;

typedef struct {
    sbx_cmd_kind_t kind;
    uint8_t        led_idx;   /* SET_LED only */
    uint8_t        r;
    uint8_t        g;
    uint8_t        b;
    uint8_t        anim_id;   /* ANIM only */
} sbx_cmd_t;

typedef enum {
    SBX_DROP_OVERFLOW   = 1, /* line longer than SBX_LINE_MAX */
    SBX_DROP_GRAMMAR    = 2, /* didn't match any production */
    SBX_DROP_RANGE      = 3, /* idx > 5 or byte > 255 */
    SBX_DROP_PARSE_TIME = 4, /* exceeded watchdog budget */
} sbx_drop_reason_t;

typedef struct {
    /* Counters, monotonic. */
    uint32_t cmd_ok;
    uint32_t drop_overflow;
    uint32_t drop_grammar;
    uint32_t drop_range;

    /* Diagnostic ring: each drop pushes 16 bytes
       (4 ts_ms_le, 1 reason, 3 reserved, 8 first_bytes). */
    rb_t     diag;
    uint8_t  diag_storage[SBX_DIAG_RING_SIZE];

    /* Line accumulator. */
    uint8_t  line[SBX_LINE_MAX];
    uint16_t line_len;
    bool     line_overflowed; /* set if we've passed SBX_LINE_MAX before LF */
} sbx_parser_t;

/* Initialise the parser. Always succeeds (statically sized). */
void sbx_parser_init(sbx_parser_t *p);

/* Feed bytes from CDC ingress. For each LF-terminated complete line,
   if it parses successfully, *out_cmd is populated and the function
   returns true (caller should dispatch). Returns false otherwise; the
   caller should keep feeding bytes. */
bool sbx_parser_feed(sbx_parser_t *p,
                     const uint8_t *bytes, uint16_t len,
                     sbx_cmd_t *out_cmd,
                     uint32_t now_ms);

/* Read up to len bytes of diagnostic frames out of the ring. Used by
   the STATUS command handler to reply to the host. */
uint16_t sbx_parser_drain_diag(sbx_parser_t *p, uint8_t *dst, uint16_t len);

#endif /* SBX_PARSER_H */
