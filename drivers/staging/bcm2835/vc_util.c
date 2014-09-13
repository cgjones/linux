/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "vc_util.h"

#include <linux/kernel.h>

int vcmem_alloc(size_t nr_bytes, size_t align_lg2, int flags,
		vcmem_handle_t* memh)
{
	VCMSG_DECL_INIT(MEM_ALLOC, msg,	{ nr_bytes, 1 << align_lg2, flags });
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	*memh = msg.out.handle;
	return 0;
}
EXPORT_SYMBOL_GPL(vcmem_alloc);


int vcmem_release(vcmem_handle_t *memh)
{
	VCMSG_DECL_INIT(MEM_RELEASE, msg, *memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	if (0 != msg.out.error) {
		pr_err("MEM_RELEASE failed with error: %u\n", msg.out.error);
		return -ENXIO;
	}
	*memh = VCMEM_HANDLE_INVALID;
	return 0;
}
EXPORT_SYMBOL_GPL(vcmem_release);


int vcmem_lock(vcmem_handle_t memh, dma_addr_t* addr)
{
	VCMSG_DECL_INIT(MEM_LOCK, msg, memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	*addr = msg.out.bus_addr;
	return 0;
}
EXPORT_SYMBOL_GPL(vcmem_lock);


int vcmem_unlock(vcmem_handle_t memh)
{
	VCMSG_DECL_INIT(MEM_UNLOCK, msg, memh);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	BUG_ON(vcmsg_out_nr_bytes(msg) != sizeof(msg.out));
	if (0 != msg.out.error) {
		pr_err("MEM_UNLOCK failed with error: %u\n", msg.out.error);
		return -ENXIO;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vcmem_unlock);


int vcqpu_set_state(u32 state)
{
	VCMSG_DECL_INIT(QPU_ENABLE_DISABLE, msg, !!state);
	int result = bcm_mailbox_property(&msg, sizeof(msg));
	if (result) {
		pr_err("Mailbox-send failed: %d\n", result);
		return result;
	}
	if (!is_vcmsg_success(msg)) {
		pr_err("VC request failed: %#x\n", msg.hdr.response);
		return -EIO;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vcqpu_set_state);
