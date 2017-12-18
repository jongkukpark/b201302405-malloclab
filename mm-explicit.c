/*
 * mm-explicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201302405 
 * @name : 박종국
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define AlIGNMENT 8

#define HDRSIZE 4
#define FTRSIZE 4
#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1<<12)
#define OVERHEAD 8

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define PACK(size, alloc) ((unsigned) ((size) | (alloc)))

#define GET(p) (*(unsigned *)(p))
#define PUT(p, val) (*(unsigned *)(p) = (unsigned)(val))
#define GET8(p) (*(unsigned long *)(p))
#define PUT8(p, val) (*(unsigned long *)(p) = (unsigned long)(val))

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE((char *)(bp) - DSIZE))

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

#define NEXT_FREEP(bp) ((char *)(bp))
#define PREV_FREEP(bp) ((char *)(bp) + WSIZE)

#define NEXT_FREE_BLKP(bp) ((char *)GET8((char *)(bp)))
#define PREV_FREE_BLKP(bp) ((char *)GET8((char *)(bp) + WSIZE))

#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    if ((h_ptr = mem_sbrk(DSIZE + 4 * HDRSIZE)) == NULL)
		return -1;
	heap_start = h_ptr;

	PUT(h_ptr, NULL);
	PUT(h_ptr + WSIZE, NULL);
	PUT(h_ptr + DSIZE, 0);
	PUT(h_ptr + DSIZE + HDRSIZE, PACK(OVERHEAD, 1));
	PUT(h_ptr + DSIZE + HDRSIZE + FTRSIZE, PACK(OVERHEAD, 1));
	PUT(h_ptr + DSIZE + 2 * HDRSIZE + FTRSIZE, PACK(0, 1));

	h_ptr += DSIZE + DSIZE;

	epilogue = h_ptr + HDRSIZE;

	if (extend_heap(CHUNKSIZE/WSIZE) == NULL)
		return -1;

	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
   	char *bp;
	unsigned asize;
	unsigned extendsize;
	
	if (size == 0)
		return NULL;
	
	if (size <= DSIZE)
		asize = 3 * DSIZE;
	else
		asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1))/ DSIZE) + DSIZE;

	if ((bp = find_fit(asize)) != NULL) {
		place(bp, asize);
		return bp;
	}

	//free list에서 적절한 블록을 찾지 못했으면 힙을 늘려서 할당

	extendsize = MAX(asize, CHUNKSIZE);
	if ((bp = extend_heap(extendsize/WSIZE)) == NULL)
		return NULL;
	place(bp, asize);
	return bp;
}

/*
 * free
 */
void free (void *bp) {
    if(bp == 0) return;
	size_t size = GET_SIZE(HDRP(bp));

	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));

	coalesce(bp);
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	size_t oldsize;
    void *newptr;

  /* If size == 0 then this is just free, and we return NULL. */
    if(size == 0) {
    	free(oldptr);
    return 0;
    }

  /* If oldptr is NULL, then this is just malloc. */
    if(oldptr == NULL) {
   		return malloc(size);
    }

    newptr = malloc(size);

  /* If realloc() fails the original block is left untouched  */
    if(!newptr) {
    	return 0;
    }

  /* Copy the old data. */
    oldsize = *SIZE_PTR(oldptr);
    if(size < oldsize) oldsize = size;
    memcpy(newptr, oldptr, oldsize);

  /* Free the old block. */
    free(oldptr);

    return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    return NULL;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}

inline void *extend_heap(size_t words) {
	unsigned *old_epilogue;
	char *bp;
	unsigned size;

	size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;

	if ((long)(bp = mem_sbrk(size)) < 0 )
		return NULL;

	old_epilogue = epilogue;
	epilogue = bp + size = HDRSIZE;

	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(epilogue, PACK(0, 1));

	return coalesce(bp);
}

static void place(void *bp, size_t asize) {
	size_t csize = GET_SIZE(HDRP(bp));

	if ((csize - asize) >= (2 * DSIZE)) {
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLKP(bp);
		PUT(HDRP(bp), PACK(csize - asize, 0));
		PUT(FTRP(bp), PACK(csize - asize, 0));
	}
	else {
		PUT(HDRP(bp), PACK(csize, 1));
		PUT(FTRP(bp), PACK(csize, 1));
	}
}
