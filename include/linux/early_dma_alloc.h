/*
 * Early DMA Memory Allocator
 *
 * Copyright © 2013 Cumulus Networks, Inc.
 *
 * Author: Curt Brune <curt@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef EARLY_DMA_ALLOC_H__
#define EARLY_DMA_ALLOC_H__

#ifdef __KERNEL__

#include <linux/types.h>

extern int eda_init(void);
extern int eda_dma_info_get(void** vaddr, uint32_t* paddr, uint32_t* size);

#endif /* __KERNEL__ */

#endif /* EARLY_DMA_ALLOC_H__ */
