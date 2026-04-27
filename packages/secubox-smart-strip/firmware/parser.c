/*
 * parser.c - CDC white-grammar parser implementation
 *
 * SecuBox / CyberMind - SBX-STR-01 v1.1
 *
 * Design notes:
 * - No dynamic allocation, no recursion, no eval, no printf-family formatting.
 * - Bounded execution: each call processes at most SBX_LINE_MAX bytes of input.
 * - Strict literal matching of keywords; case-sensitive.
 * - Numbers: decimal, no leading zeros (except "0" itself), max 3 digits, range-checked.
 * - Whitespace: exactly one space between tokens, no tabs, no extra spaces.
 * - Line terminator: single LF (0x0A). CRLF tolerated by stripping CR.
 * - Empty lines: silently ignored (no counter increment).
 */

#include "parser.h"
#include <string.h>

/* ---- Internal helpers ---- */

static void diag_record(sbx_parser_t *p, sbx_drop_reason_t reason, uint32_t ts_ms) {
    uint8_t frame[16];
    /* Little-endian timestamp. */
    frame[0] = (uint8_t)(ts_ms       & 0xFF);
    frame[1] = (uint8_t)((ts_ms >> 8)  & 0xFF);
    frame[2] = (uint8_t)((ts_ms >> 16) & 0xFF);
    frame[3] = (uint8_t)((ts_ms >> 24) & 0xFF);
    frame[4] = (uint8_t)reason;
    frame[5] = 0;
    frame[6] = 0;
    frame[7] = 0;
    /* Copy first 8 bytes of the offending line. */
    uint16_t copy = p->line_len < 8 ? p->line_len : 8;
    memcpy(&frame[8], p->line, copy);
    if (copy < 8) {
        memset(&frame[8 + copy], 0, 8 - copy);
    }
    /* Drop oldest if full (overwrite policy). */
    if (rb_free(&p->diag) < sizeof(frame)) {
        uint8_t scratch[16];
        rb_read(&p->diag, scratch, sizeof(frame));
    }
    rb_write(&p->diag, frame, sizeof(frame));
}

/* Match exact literal at position i. On success returns new position; on failure 0. */
static uint16_t match_lit(const uint8_t *line, uint16_t len, uint16_t i, const char *lit) {
    uint16_t j = 0;
    while (lit[j] != '\0') {
        if (i + j >= len) return 0;
        if (line[i + j] != (uint8_t)lit[j]) return 0;
        ++j;
    }
    return (uint16_t)(i + j);
}

/* Match exactly one space at position i. */
static uint16_t match_sp(const uint8_t *line, uint16_t len, uint16_t i) {
    if (i >= len || line[i] != ' ') return 0;
    return (uint16_t)(i + 1);
}

/*
 * Parse a decimal byte (0..255) with no leading zeros except "0".
 * Writes value to *out. Returns position after the last digit, or 0 on failure.
 */
static uint16_t parse_byte(const uint8_t *line, uint16_t len, uint16_t i, uint8_t *out) {
    if (i >= len) return 0;
    uint8_t c = line[i];
    if (c < '0' || c > '9') return 0;
    /* Leading-zero rule. */
    uint16_t start = i;
    if (c == '0') {
        *out = 0;
        return (uint16_t)(i + 1); /* lone "0" only */
    }
    uint32_t acc = 0;
    while (i < len && line[i] >= '0' && line[i] <= '9') {
        acc = acc * 10 + (uint32_t)(line[i] - '0');
        if (acc > 255) return 0;
        ++i;
        if (i - start > 3) return 0; /* max 3 digits */
    }
    *out = (uint8_t)acc;
    return i;
}

/* Parse an LED index 0..5 (single digit). */
static uint16_t parse_idx(const uint8_t *line, uint16_t len, uint16_t i, uint8_t *out) {
    if (i >= len) return 0;
    uint8_t c = line[i];
    if (c < '0' || c > '5') return 0;
    *out = (uint8_t)(c - '0');
    return (uint16_t)(i + 1);
}

/* Try each command production. Returns true on match (out_cmd populated)
   AND if the production consumed exactly len bytes (no trailing garbage). */
static bool try_parse_line(const uint8_t *line, uint16_t len, sbx_cmd_t *out_cmd,
                           sbx_drop_reason_t *out_reason) {
    uint16_t p;

    /* SET_LED idx r g b */
    if ((p = match_lit(line, len, 0, "SET_LED")) != 0) {
        uint8_t idx, r, g, b;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_idx(line, len, p, &idx)) == 0) goto range;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &r)) == 0) goto range;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &g)) == 0) goto range;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &b)) == 0) goto range;
        if (p != len) goto grammar;
        out_cmd->kind    = SBX_CMD_SET_LED;
        out_cmd->led_idx = idx;
        out_cmd->r = r; out_cmd->g = g; out_cmd->b = b;
        return true;
    }

    /* SET_ALL r g b */
    if ((p = match_lit(line, len, 0, "SET_ALL")) != 0) {
        uint8_t r, g, b;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &r)) == 0) goto range;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &g)) == 0) goto range;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &b)) == 0) goto range;
        if (p != len) goto grammar;
        out_cmd->kind = SBX_CMD_SET_ALL;
        out_cmd->r = r; out_cmd->g = g; out_cmd->b = b;
        return true;
    }

    /* ANIM id */
    if ((p = match_lit(line, len, 0, "ANIM")) != 0) {
        uint8_t id;
        if ((p = match_sp(line, len, p))      == 0) goto grammar;
        if ((p = parse_byte(line, len, p, &id)) == 0) goto range;
        if (p != len) goto grammar;
        out_cmd->kind    = SBX_CMD_ANIM;
        out_cmd->anim_id = id;
        return true;
    }

    /* Bare keywords. */
    if ((p = match_lit(line, len, 0, "HBT"))    != 0 && p == len) {
        out_cmd->kind = SBX_CMD_HBT; return true;
    }
    if ((p = match_lit(line, len, 0, "RESET"))  != 0 && p == len) {
        out_cmd->kind = SBX_CMD_RESET; return true;
    }
    if ((p = match_lit(line, len, 0, "STATUS")) != 0 && p == len) {
        out_cmd->kind = SBX_CMD_STATUS; return true;
    }

grammar:
    *out_reason = SBX_DROP_GRAMMAR;
    return false;
range:
    *out_reason = SBX_DROP_RANGE;
    return false;
}

/* ---- Public API ---- */

void sbx_parser_init(sbx_parser_t *p) {
    memset(p, 0, sizeof(*p));
    rb_init(&p->diag, p->diag_storage, SBX_DIAG_RING_SIZE);
}

bool sbx_parser_feed(sbx_parser_t *p,
                     const uint8_t *bytes, uint16_t len,
                     sbx_cmd_t *out_cmd,
                     uint32_t now_ms) {
    for (uint16_t i = 0; i < len; ++i) {
        uint8_t c = bytes[i];

        /* CR tolerance: strip silently. */
        if (c == '\r') continue;

        /* Line terminator. */
        if (c == '\n') {
            if (p->line_overflowed) {
                /* Overflow already counted; reset for next line. */
                p->line_overflowed = false;
                p->line_len = 0;
                continue;
            }
            if (p->line_len == 0) {
                /* Empty line, ignore silently. */
                continue;
            }
            sbx_drop_reason_t reason = SBX_DROP_GRAMMAR;
            if (try_parse_line(p->line, p->line_len, out_cmd, &reason)) {
                p->cmd_ok++;
                p->line_len = 0;
                return true;
            }
            /* Failed parse: account and log. */
            switch (reason) {
            case SBX_DROP_RANGE:   p->drop_range++;   break;
            default:               p->drop_grammar++; break;
            }
            diag_record(p, reason, now_ms);
            p->line_len = 0;
            continue;
        }

        /* Buffer the byte. */
        if (p->line_overflowed) {
            /* Wait for LF, but mark dropped exactly once. */
            continue;
        }
        if (p->line_len >= SBX_LINE_MAX) {
            p->drop_overflow++;
            diag_record(p, SBX_DROP_OVERFLOW, now_ms);
            p->line_overflowed = true;
            continue;
        }
        p->line[p->line_len++] = c;
    }
    return false;
}

uint16_t sbx_parser_drain_diag(sbx_parser_t *p, uint8_t *dst, uint16_t len) {
    return rb_read(&p->diag, dst, len);
}
