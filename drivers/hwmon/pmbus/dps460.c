/*
 * Hardware monitoring driver for Delta DPSXXX Power Supplies
 *
 * Copyright (C) 2015 Cumulus Networks, LLC
 * Author: Puneet Shenoy <puneet@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/i2c/pmbus.h>
#include "pmbus.h"

enum chips { dps460, dps200 };

static int dps460_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	struct pmbus_driver_info *info;
	int ret;

	if (!i2c_check_functionality(client->adapter,
				     I2C_FUNC_SMBUS_BYTE_DATA |
				     I2C_FUNC_SMBUS_WORD_DATA |
				     I2C_FUNC_SMBUS_PEC))
		return -ENODEV;

	info = kzalloc(sizeof(struct pmbus_driver_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	/* Use only 1 page with 1 Fan, 2 Temps. */
	info->pages = 1;
	info->func[0] = PMBUS_HAVE_FAN12 | PMBUS_HAVE_STATUS_FAN12 |
		PMBUS_HAVE_TEMP | PMBUS_HAVE_TEMP2 | PMBUS_HAVE_STATUS_TEMP;
	info->format[PSC_PWM] = linear;

#if 0
	if ((i2c_check_functionality(client->adapter,
				     I2C_FUNC_SMBUS_READ_I2C_BLOCK)) ||
	    (i2c_check_functionality(client->adapter,
				     I2C_FUNC_SMBUS_BLOCK_DATA)))
		info->func[0] |= PMBUS_HAVE_MFR_INFO;
#endif

	if (id->driver_data == dps200) {
		info->format[PSC_VOLTAGE_OUT] = direct;
		info->format[PSC_FAN] = linear;
	} else if (id->driver_data == dps460) {
		/* Needs PEC(PACKET ERROR CODE) for writes */
		client->flags = I2C_CLIENT_PEC;
	}

	ret = pmbus_do_probe(client, id, info);
	if (ret < 0)
		kfree(info);
	return ret;
}

static int dps460_remove(struct i2c_client *client)
{
	pmbus_do_remove(client);
	return 0;
}

static const struct i2c_device_id dps460_id[] = {
	{"dps460", dps460},
	{"dps200", dps200},
	{}
};
MODULE_DEVICE_TABLE(i2c, dps460_id);

static struct i2c_driver dps460_driver = {
	.driver = {
		   .name = "dps460",
		   },
	.probe = dps460_probe,
	.remove = dps460_remove,
	.id_table = dps460_id,
};

module_i2c_driver(dps460_driver);

MODULE_AUTHOR("Puneet Shenoy");
MODULE_DESCRIPTION("PMBus driver for Delta DPSXXX");
MODULE_LICENSE("GPL");
