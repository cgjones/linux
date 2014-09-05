#*******************************************************************************
# Copyright 2010 Broadcom Corporation.  All rights reserved.
#
# Unless you and Broadcom execute a separate written software license agreement 
# governing use of this software, this software is licensed to you under the 
# terms of the GNU General Public License version 2, available at 
# http://www.gnu.org/copyleft/gpl.html (the "GPL"). 
#
# Notwithstanding the above, under no circumstances may you combine this software 
# in any way with any other Broadcom software provided under a license other than 
# the GPL, without Broadcom's express prior written consent.
#*******************************************************************************

#EXTRA_CFLAGS += -DMEMALLOC_LINUX_ALLOC_DMA=1
obj-$(CONFIG_GE)		+= ge_drv.o gememalloc.o
obj-$(CONFIG_GE_WRAP)		+= gememalloc_wrapper.o

obj-$(CONFIG_BRCM_V3D)		+= v3d.o
obj-$(CONFIG_BRCM_V3D_OPT)	+= v3d_opt.o
