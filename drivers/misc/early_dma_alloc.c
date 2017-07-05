/*
 * Early DMA Memory Allocator
 *
 * Copyright © 2013,2014 Cumulus Networks, Inc.
 *
 * Author: Curt Brune <curt@cumulusnetworks.com>
 * Modified: Jonathan Toppins <jtoppins@cumulusnetworks.com>
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

/*
 * This driver allocates a region of DMA accessible memory, making it
 * available to one other device driver.
 *
 * The client device driver may be unloaded and reloaded over time.
 * This driver keeps the DMA region from becoming fragmented across
 * module reloads.
 *
 * Memory Region Restrictions
 * --------------------------
 * The memory region allocated by EDA MUST exist below a 4GB limit. This
 * is because EDA's primary (only at time of writing) user is the
 * Broadcom BDE driver wich assumes a 32-bit physical address space and
 * assumes paddr is no more than 32-bits wide. Furthermore, before porting
 * the BDE driver to use EDA the BDE driver specifically checked if the
 * memory region provided by highmem was less than 4GB. We assume Broadcom
 * knew what they were doing and there is a specific reason why this 4GB
 * limit is needed, so we enforce this limit by checking the physical address
 * after allocation.
 *
 * Memory Region Size and Alignment
 * --------------------------------
 * This driver allows three ways for the user to define the DMA memory
 * that will be created, listed in order of preference.
 * 1. The user may specify on the kernel command line in the boot loader
 *    the "eda_mem" option, this option has the format "size@alignment",
 *    example: eda_mem=0x04000000@0x00100000
 * 2. This driver looks for a device tree node compatible with
 *    "early-dma-alloc".  The "region_size" property of the node contains
 *    the size, in bytes, of the desired DMA memory region.  The
 *    "alignment" property contains the desired memory alignment of the
 *    region.
 * 3. Finally if neither of the above are provided the Kbuild changable,
 *    compiled in default size and alignment will be used.
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/dma-mapping.h>
#include <linux/bootmem.h>
#include <linux/early_dma_alloc.h>

#if (!defined CONFIG_EDA_DEF_SIZE) || \
	(!defined CONFIG_EDA_DEF_ALIGN)
#error incorrect kernel config - fix it
#endif

// #define DEBUG
#if (defined DEBUG)
#define eda_debug(fmt, ... ) \
	printk(KERN_ERR "eda-debug:%s(): " fmt "\n", __func__ , \
	##__VA_ARGS__)
#else
#define eda_debug(fmt, ... )
#endif

#define eda_info(fmt, ... ) \
	printk(KERN_INFO "eda: " fmt "\n", ##__VA_ARGS__)

static uint32_t dma_size;
static void     *dma_vaddr;
static u32      dma_align __initdata;
static bool     eda_cmdline  __initdata;

static int __init setup_eda_mem(char *str)
{
	char *endp;

	dma_size = memparse(str, &endp) & PAGE_MASK;
	if (*endp == '@')
		dma_align = memparse(endp + 1, NULL) & PAGE_MASK;
	eda_cmdline = true;
	return 0;
}
early_param("eda_mem", setup_eda_mem);

static int __init of_eda_init(uint32_t *size, u32 *align)
#ifdef CONFIG_OF_FLATTREE
{
	int                 rc           = -ENODEV;
	struct device_node  *np          = NULL;
	const u32           *region_sz_p = NULL;
	const u32           *align_p     = NULL;
	u32                 prop_sz      = 0;

	eda_debug("entry");

	/* is a programming error make it really painful so it gets fixed */
	BUG_ON(NULL == size || NULL == align);

	np = of_find_compatible_node(NULL, NULL, "early-dma-alloc");
	if (!np) {
		printk(KERN_WARNING "WARN: Can not find `early-dma-alloc'"
		       " device tree node.\n");
		goto cleanup;
	}

	region_sz_p = of_get_property(np, "region_size", &prop_sz);
	if (!region_sz_p || (prop_sz != sizeof(*region_sz_p))) {
		printk(KERN_ERR "ERROR: Can not find `region_size' property"
		       " in early-dma-alloc device tree node.\n");
		goto cleanup;
	}
	*size = *region_sz_p;

	align_p = of_get_property(np, "alignment", &prop_sz);
	if (!align_p || (prop_sz != sizeof(*align_p))) {
		printk(KERN_ERR "ERROR: Can not find `alignment' property in"
		       "early-dma-alloc device tree node.\n");
		goto cleanup;
	}
	*align = *align_p;
	rc = 0;

	eda_debug("cleanup");

cleanup:
	of_node_put(np);
	return rc;

}
#else
{
	return -ENODEV;
}
#endif

int eda_dma_info_get(void **vaddr, uint32_t *paddr, uint32_t *size)
{
	eda_debug("entry");

	if (!dma_vaddr)
		return -ENOMEM;

	if (!vaddr || !paddr || !size)
		return -EINVAL;

	*vaddr = dma_vaddr;
	*paddr = (uint32_t) virt_to_phys(dma_vaddr);
	*size  = dma_size;

	eda_debug("returning -- dma_vaddr: 0x%pK, dma_paddr: 0x%08x,"
	          " size: 0x%08x", *vaddr, *paddr, *size);

	return 0;
}
EXPORT_SYMBOL(eda_dma_info_get);

int __init eda_init(void)
{
	int rc    = 0;

	if (eda_cmdline) {
		if (!dma_align)
			dma_align = CONFIG_EDA_DEF_ALIGN;
		if (!dma_size)
			dma_size  = CONFIG_EDA_DEF_SIZE;
		eda_debug("size & alignment came from: kernel cmdline");
	} else if (!of_eda_init(&dma_size, &dma_align)) {
		eda_debug("size & alignment came from: open firmware entry");
	} else {
		dma_align = CONFIG_EDA_DEF_ALIGN;
		dma_size  = CONFIG_EDA_DEF_SIZE;
		eda_debug("size & alignment came from: compiled in defaults");
	}

	dma_vaddr = __alloc_bootmem_low(dma_size, dma_align, 0);
	/*
	 * enforce EDA's requirement to allocate the memory region below a
	 * 32-bit limit.
	 */
	if (virt_to_phys(dma_vaddr) > 0xFFFFFFFFULL) {
		rc = -ENOMEM;
		printk(KERN_ERR "ERROR: DMA memory beyond 32-bit address"
		       " space not supported.\n");
		goto cleanup;
	}

	eda_info("dma_vaddr: 0x%pK, dma_paddr: 0x%016llx, size: 0x%08x,"
	         " alignment: 0x%08x",
		 dma_vaddr, (unsigned long long) virt_to_phys(dma_vaddr),
		 dma_size, dma_align);
cleanup:
	if (rc && dma_vaddr) {
		free_bootmem((unsigned long)dma_vaddr, dma_size);
	}
	if (rc) {
		dma_vaddr = NULL;
		dma_size  = 0;
	}
	return rc;
}
EXPORT_SYMBOL(eda_init);
