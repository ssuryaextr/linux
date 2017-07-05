/*
 * eeprom_class.h
 *
 * This file exports interface functions for the sysfs class "eeprom",
 * for use by EEPROM drivers.
 *
 * Copyright (C) 2013 Cumulus Networks, Inc.
 * Author: Curt Brune <curt@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef EEPROM_CLASS_H__
#define EEPROM_CLASS_H__

#include <linux/device.h>
#include <linux/err.h>

/*
 * Extra platform data used by the eeprom class
 *
 * An eeprom device can include this structure in its own platform
 * data structure.
 *
 * A specific platform can set the values in this structure to values
 * suitable for that platform.
 *
 */
struct eeprom_platform_data {
	char	*label; /* device label to use with the eeprom class */
};

/*
 * EEPROM device structure
 *
 * This structure is used by the eeprom_class driver to manage the
 * state of the class device.
 *
 */
struct eeprom_device {
	struct device	*dev;
	struct eeprom_platform_data	*data;
};

#if defined(CONFIG_EEPROM_CLASS) || defined (CONFIG_EEPROM_CLASS_MODULE)

extern struct eeprom_device *
eeprom_device_register(struct device *dev, struct eeprom_platform_data *data);
extern void
eeprom_device_unregister(struct eeprom_device *eeprom_dev);

#else

static inline struct eeprom_device *
eeprom_device_register(struct device *dev, char *label)
{
	return NULL;
}

static inline void
eeprom_device_unregister(struct eeprom_device *eeprom_dev)
{
}

#endif

#endif /* EEPROM_CLASS_H__ */
