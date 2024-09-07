/*
 * Declarations for cpu physical memory functions
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Avi Kivity <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

/*
 * This header is for use by exec.c and memory.c ONLY.  Do not include it.
 * The functions declared here will be removed soon.
 */

#ifndef QEMU_EXEC_RAMBLOCK_H
#define QEMU_EXEC_RAMBLOCK_H

#ifndef CONFIG_USER_ONLY
#include "cpu-common.h"
#include "qemu/rcu.h"
#include "exec/ramlist.h"

/* Possible bits for cpu_physical_memory_sync_dirty_bitmap */

/*
 * The old-fashioned sync, which is, in turn, used for CPU
 * throttle and memory transfer.
 */
#define RAMBLOCK_SYN_LEGACY_ITER   (1U << 0)

/*
 * The modern sync, which is, in turn, used for CPU throttle
 * and memory transfer.
 */
#define RAMBLOCK_SYN_MODERN_ITER   (1U << 1)

/* The modern sync, which is used for CPU throttle only */
#define RAMBLOCK_SYN_MODERN_BACKGROUND    (1U << 2)

#define RAMBLOCK_SYN_MASK  (0x7)

typedef enum RAMBlockSynMode {
    RAMBLOCK_SYN_LEGACY, /* Old-fashined mode */
    RAMBLOCK_SYN_MODERN, /* Background-sync-supported mode */
} RAMBlockSynMode;

struct RAMBlock {
    struct rcu_head rcu;
    struct MemoryRegion *mr;
    uint8_t *host;
    uint8_t *colo_cache; /* For colo, VM's ram cache */
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    /* Protected by the BQL.  */
    char idstr[256];
    /* RCU-enabled, writes protected by the ramlist lock */
    QLIST_ENTRY(RAMBlock) next;
    QLIST_HEAD(, RAMBlockNotifier) ramblock_notifiers;
    int fd;
    uint64_t fd_offset;
    int guest_memfd;
    size_t page_size;
    /* dirty bitmap used during migration */
    unsigned long *bmap;

    /*
     * Below fields are only used by mapped-ram migration
     */
    /* bitmap of pages present in the migration file */
    unsigned long *file_bmap;
    /*
     * offset in the file pages belonging to this ramblock are saved,
     * used only during migration to a file.
     */
    off_t bitmap_offset;
    uint64_t pages_offset;

    /* Bitmap of already received pages.  Only used on destination side. */
    unsigned long *receivedmap;

    /*
     * bitmap to track already cleared dirty bitmap.  When the bit is
     * set, it means the corresponding memory chunk needs a log-clear.
     * Set this up to non-NULL to enable the capability to postpone
     * and split clearing of dirty bitmap on the remote node (e.g.,
     * KVM).  The bitmap will be set only when doing global sync.
     *
     * It is only used during src side of ram migration, and it is
     * protected by the global ram_state.bitmap_mutex.
     *
     * NOTE: this bitmap is different comparing to the other bitmaps
     * in that one bit can represent multiple guest pages (which is
     * decided by the `clear_bmap_shift' variable below).  On
     * destination side, this should always be NULL, and the variable
     * `clear_bmap_shift' is meaningless.
     */
    unsigned long *clear_bmap;
    uint8_t clear_bmap_shift;

    /*
     * RAM block length that corresponds to the used_length on the migration
     * source (after RAM block sizes were synchronized). Especially, after
     * starting to run the guest, used_length and postcopy_length can differ.
     * Used to register/unregister uffd handlers and as the size of the received
     * bitmap. Receiving any page beyond this length will bail out, as it
     * could not have been valid on the source.
     */
    ram_addr_t postcopy_length;

    /*
     * Used to backup the bmap during background sync to see whether any dirty
     * pages were sent during that time.
     */
    unsigned long *shadow_bmap;

    /*
     * The bitmap "bmap," which was initially used for both sync and memory
     * transfer, will be replaced by two bitmaps: the previously used "bmap"
     * and the recently added "iter_bmap." Only the memory transfer is
     * conducted with the previously used "bmap"; the recently added
     * "iter_bmap" is utilized for dirty bitmap sync.
     */
    unsigned long *iter_bmap;

    /* Number of new dirty pages during iteration */
    uint64_t iter_dirty_pages;

    /* If background sync has shown up during iteration */
    bool background_sync_shown_up;
};
#endif
#endif
