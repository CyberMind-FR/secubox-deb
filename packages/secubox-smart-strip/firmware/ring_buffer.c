/*
 * ring_buffer.c - SPSC FIFO byte buffer implementation
 *
 * SecuBox / CyberMind - SBX-STR-01 v1.1
 */

#include "ring_buffer.h"

/* Verify n is a power of two and non-zero. */
static inline bool is_pow2(uint16_t n) {
    return n != 0 && (n & (n - 1)) == 0;
}

bool rb_init(rb_t *rb, uint8_t *storage, uint16_t capacity) {
    if (rb == NULL || storage == NULL || !is_pow2(capacity)) {
        return false;
    }
    rb->buf      = storage;
    rb->capacity = capacity;
    rb->mask     = (uint16_t)(capacity - 1u);
    rb->head     = 0;
    rb->tail     = 0;
    return true;
}

uint16_t rb_used(const rb_t *rb) {
    /* Unsigned wrap arithmetic gives correct result. */
    return (uint16_t)(rb->head - rb->tail);
}

uint16_t rb_free(const rb_t *rb) {
    return (uint16_t)(rb->capacity - rb_used(rb));
}

bool rb_empty(const rb_t *rb) { return rb->head == rb->tail; }
bool rb_full(const rb_t *rb)  { return rb_used(rb) == rb->capacity; }

uint16_t rb_write(rb_t *rb, const uint8_t *src, uint16_t len) {
    uint16_t avail = rb_free(rb);
    uint16_t n = (len < avail) ? len : avail;
    for (uint16_t i = 0; i < n; ++i) {
        rb->buf[(rb->head + i) & rb->mask] = src[i];
    }
    /* Memory barrier on multi-core. On RP2350 we rely on the compiler
       not to reorder past this volatile write. For full SMP safety,
       wrap in __sync_synchronize() or rp2350-sdk multicore primitive. */
    rb->head = (uint16_t)(rb->head + n);
    return n;
}

uint16_t rb_read(rb_t *rb, uint8_t *dst, uint16_t len) {
    uint16_t avail = rb_used(rb);
    uint16_t n = (len < avail) ? len : avail;
    for (uint16_t i = 0; i < n; ++i) {
        dst[i] = rb->buf[(rb->tail + i) & rb->mask];
    }
    rb->tail = (uint16_t)(rb->tail + n);
    return n;
}

void rb_reset(rb_t *rb) {
    rb->head = 0;
    rb->tail = 0;
}
