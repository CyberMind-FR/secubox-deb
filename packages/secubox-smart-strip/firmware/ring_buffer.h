/*
 * ring_buffer.h - Lock-free single-producer single-consumer FIFO byte buffer
 *
 * Used by the Smart-Strip firmware for:
 *   - CDC USB ingress (USB IRQ writes, parser task reads)
 *   - Diagnostic log ring (parser writes drops/errors, STATUS cmd reads)
 *
 * Power-of-2 capacity required (mask-based wraparound, no modulo).
 *
 * SecuBox / CyberMind - SBX-STR-01 v1.1
 */

#ifndef SBX_RING_BUFFER_H
#define SBX_RING_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint8_t  *buf;
    uint16_t  capacity;   /* power of 2 */
    uint16_t  mask;       /* capacity - 1 */
    volatile uint16_t head; /* write index, producer */
    volatile uint16_t tail; /* read  index, consumer */
} rb_t;

/* Initialise. capacity MUST be a power of 2. Returns false otherwise. */
bool     rb_init(rb_t *rb, uint8_t *storage, uint16_t capacity);

/* Producer side. Returns number of bytes actually written (may be < len if full). */
uint16_t rb_write(rb_t *rb, const uint8_t *src, uint16_t len);

/* Consumer side. Returns number of bytes actually read (may be < len if empty). */
uint16_t rb_read(rb_t *rb, uint8_t *dst, uint16_t len);

/* Inspectors (cheap, no locking). */
uint16_t rb_used(const rb_t *rb);
uint16_t rb_free(const rb_t *rb);
bool     rb_empty(const rb_t *rb);
bool     rb_full(const rb_t *rb);

/* Wipe contents. NOT safe to call concurrent with producer/consumer. */
void     rb_reset(rb_t *rb);

#endif /* SBX_RING_BUFFER_H */
