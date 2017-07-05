/*
 * eeprom_class.c
 *
 * This file defines the sysfs class "eeprom", for use by EEPROM
 * drivers.
 *
 * Copyright (C) 2013 Cumulus Networks, Inc.
 * Author: Curt Brune <curt@cumulusnetworks.com>
 *
 * Ideas and structure graciously borrowed from the hwmon class:
 * Copyright (C) 2005 Mark M. Hoffman <mhoffman@lightlink.com>
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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kdev_t.h>
#include <linux/idr.h>
#include <linux/eeprom_class.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>
#include <linux/pci.h>
#include <linux/of.h>

/* Root eeprom "class" object (corresponds to '/<sysfs>/class/eeprom_dev/') */
static struct class *eeprom_class;

#define EEPROM_CLASS_NAME "eeprom_dev"
#define EEPROM_ID_PREFIX "eeprom"
#define EEPROM_ID_FORMAT EEPROM_ID_PREFIX "%d"

static DEFINE_IDA(eeprom_ida);

/**
 * eeprom_device_register - register w/ eeprom class
 * @dev: the device to register
 * @data: platform data to use for the device
 *
 * eeprom_device_unregister() must be called when the device is no
 * longer needed.
 *
 * Creates a new eeprom class device that is a child of @dev.  Also
 * creates a symlink in /<sysfs>/class/eeprom_dev/eeprom[N] pointing
 * to the new device.
 *
 * Returns the pointer to the new device.
 */
struct eeprom_device *eeprom_device_register(struct device *dev, struct eeprom_platform_data *data)
{
	struct eeprom_device *eeprom_dev;
	int id;
	int ret;

	id = ida_simple_get(&eeprom_ida, 0, 0, GFP_KERNEL);
	if (id < 0)
		return ERR_PTR(id);

	eeprom_dev = kzalloc(sizeof(struct eeprom_device), GFP_KERNEL);
	if (!eeprom_dev) {
		ret = -ENOMEM;
		goto err_ida;
	}

	eeprom_dev->dev = device_create(eeprom_class, dev, MKDEV(0, 0),
					eeprom_dev, EEPROM_ID_FORMAT, id);
	if (IS_ERR(eeprom_dev->dev)) {
		ret = PTR_ERR(eeprom_dev->dev);
		goto err_eeprom_dev_free;
	}

	eeprom_dev->data = data;

	return eeprom_dev;

err_eeprom_dev_free:
	kfree(eeprom_dev);

err_ida:
	ida_simple_remove(&eeprom_ida, id);
	return ERR_PTR(ret);
}

/**
 * eeprom_device_unregister - removes the previously registered class device
 *
 * @eeprom: the eeprom class device to destroy
 */
void eeprom_device_unregister(struct eeprom_device *eeprom_dev)
{
	int id;

	if (likely(sscanf(dev_name(eeprom_dev->dev), EEPROM_ID_FORMAT, &id) == 1)) {
		device_unregister(eeprom_dev->dev);
		kfree(eeprom_dev);
		ida_simple_remove(&eeprom_ida, id);
	} else
		dev_dbg(eeprom_dev->dev->parent,
			"eeprom_device_unregister() failed: bad class ID!\n");
}

/**
 * Each member of the eeprom class exports a sysfs file called
 * "label", containing the label property from the corresponding
 * device tree node.
 *
 *  Userspace can use the label to identify what the EEPROM is for.
 */
static ssize_t label_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	struct eeprom_device *eeprom_dev = (struct eeprom_device *)dev_get_drvdata(dev);
	const char* cp = NULL;
	int len = 0;

	/* Check if the eeprom device has an explicit label:
	 * - explicitly passed in to eeprom_device_register()
	 * - explicitly passed via the device tree node
	 *
	 * Otherwise use "unknown".
	 */
	if (eeprom_dev->data && eeprom_dev->data->label) {
		cp = eeprom_dev->data->label;
		len = strlen(cp) + 1;
	} else {
		/*
		 * Check for a device tree property.
		 *
		 * The class device is a child of the original device,
		 * i.e. dev->parent points to the original device.
		 */
		if (dev->parent && dev->parent->of_node)
			cp = of_get_property(dev->parent->of_node, "label", &len);
	}

	if ((cp == NULL) || (len == 0)) {
		cp = "unknown";
		len = strlen(cp) + 1;
	}

	strncpy(buf, cp, len - 1);
	buf[len - 1] = '\n';
	buf[len] = '\0';

	return len;
}

static DEVICE_ATTR_RO(label);

struct attribute *eeprom_class_dev_attrs[] = {
	&dev_attr_label.attr,
	NULL,
};

ATTRIBUTE_GROUPS(eeprom_class_dev);

static int __init eeprom_init(void)
{
	eeprom_class = class_create(THIS_MODULE, EEPROM_CLASS_NAME);
	if (IS_ERR(eeprom_class)) {
		pr_err("couldn't create sysfs class\n");
		return PTR_ERR(eeprom_class);
	}

	eeprom_class->dev_groups = eeprom_class_dev_groups;

	return 0;
}

static void __exit eeprom_exit(void)
{
	class_destroy(eeprom_class);
}

subsys_initcall(eeprom_init);
module_exit(eeprom_exit);

EXPORT_SYMBOL_GPL(eeprom_device_register);
EXPORT_SYMBOL_GPL(eeprom_device_unregister);

MODULE_AUTHOR("Curt Brune <curt@cumulusnetworks.com>");
MODULE_DESCRIPTION("eeprom sysfs/class support");
MODULE_LICENSE("GPL v2");
