/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef _BCM2708_VC_UTIL_H
#define _BCM2708_VC_UTIL_H


#include <linux/types.h>

#include <mach/vcio.h>

/*-----------------------------------------------------------------------------
 * vcio.h ?
 */

#define max_sizeof(_a, _b)					\
	(sizeof(_a) > sizeof(_b) ? sizeof(_a) : sizeof(_b))

enum {
	VCMSG_OUTPARAMS_SIZE_MASK 	= ~VCMSG_REQUEST_SUCCESSFUL,
};

enum {
	VCMSG_MEM_ALLOC			= 0x0003000c,
	VCMSG_MEM_RELEASE		= 0x0003000f,
	VCMSG_MEM_LOCK			= 0x0003000d,
	VCMSG_MEM_UNLOCK		= 0x0003000e,
	VCMSG_QPU_ENABLE_DISABLE	= 0x00030012,
};

struct vcmsg_header {
	u32 msg_nr_bytes;
	u32 response;
	u32 tag;
	u32 buf_nr_bytes;
	union {
		u32 in_nr_bytes;
		u32 out_nr_bytes;
	};
};

struct vcmsg_footer {
	u32 end_tag;
};

#define VCMSG_TYPENAME(_tag)			\
	struct VCMSG_ ## _tag ## _struct

#define VCMSG_DEFINE(_tag, _inparams, _outparams)	\
	VCMSG_TYPENAME(_tag) {				\
		struct vcmsg_header hdr;		\
		union {					\
			struct {			\
				_inparams;		\
			} in;				\
			struct {			\
				_outparams;		\
			} out;				\
		};					\
		struct vcmsg_footer ftr;		\
	}

#define VCMSG_DECL(_tag, _var)			\
	VCMSG_TYPENAME(_tag) _var

#define VCMSG_SIZEOF_BUF(_m)				\
	(max_sizeof((_m).in, (_m).out))

#define VCMSG_DECL_INIT(_tag, _var, ...)				\
	VCMSG_DECL(_tag, _var) = {					\
		.hdr = {						\
			.msg_nr_bytes = sizeof(VCMSG_TYPENAME(_tag)),	\
			.response = 0,					\
			.tag = VCMSG_ ## _tag,				\
			.buf_nr_bytes = VCMSG_SIZEOF_BUF(_var),		\
			.in_nr_bytes = sizeof(_var.in),			\
		},							\
		.in = { __VA_ARGS__ },					\
		.ftr = { VCMSG_PROPERTY_END }				\
	}

#define is_vcmsg_success(_m)					\
	(VCMSG_REQUEST_SUCCESSFUL == (_m).hdr.response)

#define vcmsg_out_nr_bytes(_m)				\
	(VCMSG_OUTPARAMS_SIZE_MASK & (_m).hdr.out_nr_bytes)


VCMSG_DEFINE(MEM_ALLOC,
	     struct {
		     u32 size_bytes;
		     u32 align;
		     u32 flags;
	     },
	     u32 handle);

VCMSG_DEFINE(MEM_RELEASE,
	     u32 handle,
	     u32 error);

VCMSG_DEFINE(MEM_LOCK,
	     u32 handle,
	     u32 bus_addr);

VCMSG_DEFINE(MEM_UNLOCK,
	     u32 handle,
	     u32 error);

VCMSG_DEFINE(QPU_ENABLE_DISABLE,
	     u32 enable_disable,
	     );

/*-----------------------------------------------------------------------------
 * vc_mem.h ?
 */
enum {
	VCMEM_FLAG_NONE			= 0,

	/*
	 * If a MEM_HANDLE_T is discardable, the memory manager may
	 * resize it to size 0 at any time when it is not locked or
	 * retained.
	 */
	VCMEM_FLAG_DISCARDABLE		= 1 << 0,
	/*
	 * If a MEM_HANDLE_T is allocating (or normal), its block of
	 * memory will be accessed in an allocating fashion through
	 * the cache.
	 */
	VCMEM_FLAG_NORMAL		= 0 << 2,
	VCMEM_FLAG_ALLOCATING		= VCMEM_FLAG_NORMAL,
	/*
	 * If a MEM_HANDLE_T is direct, its block of memory will be
	 * accessed directly, bypassing the cache.
	 */
	VCMEM_FLAG_DIRECT		= 1 << 2,
	/*
	 * If a MEM_HANDLE_T is coherent, its block of memory will be
	 * accessed in a non-allocating fashion through the cache.
	 */
	VCMEM_FLAG_COHERENT		= 2 << 2,
	/*
	 * If a MEM_HANDLE_T is L1-nonallocating, its block of memory
	 * will be accessed by the VPU in a fashion which is
	 * allocating in L2, but only coherent in L1.
	 */
	VCMEM_FLAG_L1_NONALLOCATING	= (VCMEM_FLAG_DIRECT |
					   VCMEM_FLAG_COHERENT),

	/*
	 * If a MEM_HANDLE_T is zero'd, its contents are set to 0
	 * rather than MEM_HANDLE_INVALID on allocation and resize up.
	 */
	VCMEM_FLAG_ZERO			= 1 << 4,
	/*
	 * If a MEM_HANDLE_T is uninitialised, it will not be reset to
	 * a defined value (either zero, or all 1's) on allocation.
	*/
	VCMEM_FLAG_NO_INIT		= 1 << 5,
	VCMEM_FLAG_INIT			= 0 << 5,

	/*
	 * Likely to be locked for long periods of time.
	 */
	VCMEM_FLAG_HINT_PERMALOCK	= 1 << 6,
	/*
	 * Likely to grow in size over time. If this flag is
	 * specified, MEM_FLAG_RESIZEABLE must also be.
	 */
	VCMEM_FLAG_HINT_GROW		= 1 << 7,

	/*
	 * If a MEM_HANDLE_T is to be resized with mem_resize, this
	 * flag must be present. This flag prevents things from being
	 * allocated out of the small allocation pool.
	 */
	VCMEM_FLAG_RESIZEABLE		= 1 << 8,
};
enum {
	VCMEM_HANDLE_INVALID	 	= 0x00000000ul,
	VCMEM_HANDLE_ZERO_SIZE_HANDLE	= 0x80000000ul,
	VCMEM_HANDLE_EMPTY_STRING_HANDLE= 0x80000001ul,
	VCMEM_HANDLE_FORCE_32_BIT 	= 0x80000000ul,
};

typedef u32 vcmem_handle_t;

extern int vcmem_alloc(size_t nr_bytes, size_t align_lg2, int flags,
		       vcmem_handle_t* memh);
extern int vcmem_release(vcmem_handle_t *memh);
extern int vcmem_lock(vcmem_handle_t memh, dma_addr_t* addr);
extern int vcmem_unlock(vcmem_handle_t memh);

enum {
	VCQPU_DISABLED	 		= 0,
	VCQPU_ENABLED	 		= 1,
};

extern int vcqpu_set_state(u32 state);

#endif /* _BCM2708_VC_UTIL_H */
