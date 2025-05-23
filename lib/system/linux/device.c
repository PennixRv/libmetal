/*
 * Copyright (c) 2015, Xilinx Inc. and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * @file	linux/device.c
 * @brief	Linux libmetal device operations.
 */

#include "metal/log.h"
#include <metal/bus.h>
#include <metal/uio.h>
#include <metal/vfio.h>
#include <metal/sys.h>
#include <metal/utilities.h>
#include <metal/irq.h>
#include <metal/device.h>
#include <linux/vfio.h>


/* VFIO IRQ action types */
#ifndef VFIO_IRQ_SET_ACTION_ACK
#define VFIO_IRQ_SET_ACTION_ACK		(1 << 3)
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// static struct linux_bus *to_linux_bus(struct metal_bus *bus)
// {
// 	return metal_container_of(bus, struct linux_bus, bus);
// }

// static struct linux_device *to_linux_device(struct metal_device *device)
// {
// 	return metal_container_of(device, struct linux_device, device);
// }

static struct linux_bus linux_bus[] = {
	{
		.bus_name	= "platform",
		.drivers = {
			{
				.drv_name  = "uio_pdrv_genirq",
				.mod_name  = "uio_pdrv_genirq",
				.cls_name  = "uio",
				.dev_open  = metal_uio_dev_open,
				.dev_close = metal_uio_dev_close,
				.dev_irq_ack  = metal_uio_dev_irq_ack,
				.dev_dma_map = metal_uio_dev_dma_map,
				.dev_dma_unmap = metal_uio_dev_dma_unmap,
			},
			{
				.drv_name  = "uio_dmem_genirq",
				.mod_name  = "uio_dmem_genirq",
				.cls_name  = "uio",
				.dev_open  = metal_uio_dev_open,
				.dev_close = metal_uio_dev_close,
				.dev_irq_ack  = metal_uio_dev_irq_ack,
				.dev_dma_map = metal_uio_dev_dma_map,
				.dev_dma_unmap = metal_uio_dev_dma_unmap,
			},
			{ 0 /* sentinel */ }
		}
	},
	{
		.bus_name	= "pci",
		.drivers = {
			{
				.drv_name      = "vfio-pci",
				.mod_name      = "vfio-pci",
				.cls_name      = "pci",
				.dev_open      = metal_vfio_dev_open,
				.dev_close     = metal_vfio_dev_close,
				.dev_irq_ack   = metal_vfio_dev_irq_ack,
				.dev_dma_map   = metal_vfio_dev_dma_map,
				.dev_dma_unmap = metal_vfio_dev_dma_unmap,
			},
			// {
			// 	.drv_name  = "uio_pci_generic",
			// 	.mod_name  = "uio_pci_generic",
			// 	.cls_name  = "uio",
			// 	.dev_open  = metal_uio_dev_open,
			// 	.dev_close = metal_uio_dev_close,
			// 	.dev_irq_ack  = metal_uio_dev_irq_ack,
			// 	.dev_dma_map = metal_uio_dev_dma_map,
			// 	.dev_dma_unmap = metal_uio_dev_dma_unmap,
			// },
			{ 0 /* sentinel */ }
		}
	},
	{
		/* sentinel */
		.bus_name = NULL,
	},
};

#define for_each_linux_bus(lbus)					\
	for ((lbus) = linux_bus; (lbus)->bus_name; (lbus)++)
#define for_each_linux_driver(lbus, ldrv)			\
	for ((ldrv) = lbus->drivers; (ldrv)->drv_name; (ldrv)++)


static int metal_linux_dev_open(struct metal_bus *bus,
				const char *dev_name,
				struct metal_device **device)
{
	struct linux_bus *lbus = to_linux_bus(bus);
	struct linux_device *ldev = NULL;
	struct linux_driver *ldrv;
	int error;
	struct sysfs_device *sdev;

	/* First check if device exists and is already bound */
	sdev = sysfs_open_device(lbus->bus_name, dev_name);
	if (!sdev)
		return -ENODEV;

	/* If already bound to a driver, use that driver only */
	if (sdev->driver_name[0] && strcmp(sdev->driver_name, SYSFS_UNKNOWN) != 0) {
		for_each_linux_driver(lbus, ldrv) {
			if (/* strcmp(ldrv->drv_name, sdev->driver_name) == 0 */1) {
				ldev = malloc(sizeof(*ldev));
				if (!ldev) {
					sysfs_close_device(sdev);
					return -ENOMEM;
				}

				memset(ldev, 0, sizeof(*ldev));
				strncpy(ldev->dev_name, dev_name, sizeof(ldev->dev_name) - 1);
				ldev->fd = -1;
				ldev->ldrv = ldrv;
				ldev->device.bus = bus;
				ldev->sdev = sdev;

				error = ldrv->dev_open(lbus, ldev);
				if (error) {
					free(ldev);
					sysfs_close_device(sdev);
					return error;
				}

				*device = &ldev->device;
				(*device)->name = ldev->dev_name;
				metal_list_add_tail(&bus->devices, &(*device)->node);
				return 0;
			}
		}
		sysfs_close_device(sdev);
		return -ENODEV;
	}

	/* Device not bound - try all compatible drivers */
	ldev = malloc(sizeof(*ldev));
	if (!ldev) {
		sysfs_close_device(sdev);
		return -ENOMEM;
	}

	for_each_linux_driver(lbus, ldrv) {
		if (!ldrv->sdrv || !ldrv->dev_open)
			continue;

		memset(ldev, 0, sizeof(*ldev));
		strncpy(ldev->dev_name, dev_name, sizeof(ldev->dev_name) - 1);
		ldev->fd = -1;
		ldev->ldrv = ldrv;
		ldev->device.bus = bus;
		ldev->sdev = sdev;

		error = ldrv->dev_open(lbus, ldev);
		if (error) {
			ldrv->dev_close(lbus, ldev);
			continue;
		}

		*device = &ldev->device;
		(*device)->name = ldev->dev_name;
		metal_list_add_tail(&bus->devices, &(*device)->node);
		return 0;
	}

	free(ldev);
	sysfs_close_device(sdev);

	return -ENODEV;
}

static void metal_linux_dev_close(struct metal_bus *bus,
				  struct metal_device *device)
{
	struct linux_device *ldev = to_linux_device(device);
	struct linux_bus *lbus = to_linux_bus(bus);

	if (!ldev || !ldev->ldrv || !ldev->ldrv->dev_close) {
		metal_log(METAL_LOG_ERROR, "%s: invalid device state\n", __func__);
		return;
	}

	/* Ensure all pending operations are complete */
	if (ldev->ldrv->dev_dma_unmap) {
		/* Unmap all DMA regions */
		struct metal_sg sg = {0};
		ldev->ldrv->dev_dma_unmap(lbus, ldev,
			VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
			&sg, 1);
	}

	/* Close device through driver */
	ldev->ldrv->dev_close(lbus, ldev);

	/* Clean up resources */
	if (ldev->sdev) {
		sysfs_close_device(ldev->sdev);
		ldev->sdev = NULL;
	}

	metal_list_del(&device->node);
	free(ldev);
}

static void metal_linux_bus_close(struct metal_bus *bus)
{
	struct linux_bus *lbus = to_linux_bus(bus);
	struct linux_driver *ldrv;

	for_each_linux_driver(lbus, ldrv) {
		if (ldrv->sdrv)
			sysfs_close_driver(ldrv->sdrv);
		ldrv->sdrv = NULL;
	}

	sysfs_close_bus(lbus->sbus);
	lbus->sbus = NULL;
}

static void metal_linux_dev_irq_ack(struct metal_bus *bus,
			     struct metal_device *device,
			     int irq)
{
	struct linux_device *ldev = to_linux_device(device);
	struct linux_bus *lbus = to_linux_bus(bus);

	ldev->ldrv->dev_irq_ack(lbus, ldev, irq);
}

static int metal_linux_dev_dma_map(struct metal_bus *bus,
			     struct metal_device *device,
			     uint32_t dir,
			     struct metal_sg *sg_in,
			     int nents_in,
			     struct metal_sg *sg_out)
{
	struct linux_device *ldev = to_linux_device(device);
	struct linux_bus *lbus = to_linux_bus(bus);

	return ldev->ldrv->dev_dma_map(lbus, ldev, dir, sg_in,
				       nents_in, sg_out);
}

static void metal_linux_dev_dma_unmap(struct metal_bus *bus,
				      struct metal_device *device,
				      uint32_t dir,
				      struct metal_sg *sg,
				      int nents)
{
	struct linux_device *ldev = to_linux_device(device);
	struct linux_bus *lbus = to_linux_bus(bus);

	ldev->ldrv->dev_dma_unmap(lbus, ldev, dir, sg,
				       nents);
}

static const struct metal_bus_ops metal_linux_bus_ops = {
	.bus_close	= metal_linux_bus_close,
	.dev_open	= metal_linux_dev_open,
	.dev_close	= metal_linux_dev_close,
	.dev_irq_ack	= metal_linux_dev_irq_ack,
	.dev_dma_map	= metal_linux_dev_dma_map,
	.dev_dma_unmap	= metal_linux_dev_dma_unmap,
};

static int metal_linux_register_bus(struct linux_bus *lbus)
{
	lbus->bus.name = lbus->bus_name;
	lbus->bus.ops  = metal_linux_bus_ops;
	return metal_bus_register(&lbus->bus);
}

static int metal_linux_probe_driver(struct linux_bus *lbus,
				    struct linux_driver *ldrv)
{
	char command[256];
	int ret;

	ldrv->sdrv = sysfs_open_driver(lbus->bus_name, ldrv->drv_name);

	/* Try probing the module and then open the driver. */
	if (!ldrv->sdrv) {
		ret = snprintf(command, sizeof(command),
			       "modprobe %s > /dev/null 2>&1", ldrv->mod_name);
		if (ret >= (int)sizeof(command))
			return -EOVERFLOW;
		ret = system(command);
		if (ret < 0) {
			metal_log(METAL_LOG_WARNING,
				  "%s: executing system command'%s'failed.\n",
				  __func__, command);
		}
		ldrv->sdrv = sysfs_open_driver(lbus->bus_name, ldrv->drv_name);
	}

	/* Try sudo probing the module and then open the driver. */
	if (!ldrv->sdrv) {
		ret = snprintf(command, sizeof(command),
			       "sudo modprobe %s > /dev/null 2>&1", ldrv->mod_name);
		if (ret >= (int)sizeof(command))
			return -EOVERFLOW;
		ret = system(command);
		if (ret < 0) {
			metal_log(METAL_LOG_WARNING,
				  "%s: executing system command'%s'failed.\n",
				  __func__, command);
		}
		ldrv->sdrv = sysfs_open_driver(lbus->bus_name, ldrv->drv_name);
	}

	/* If all else fails... */
	return ldrv->sdrv ? 0 : -ENODEV;
}

static int metal_linux_probe_bus(struct linux_bus *lbus)
{
	struct linux_driver *ldrv;
	int ret, error = -ENODEV;

	lbus->sbus = sysfs_open_bus(lbus->bus_name);
	if (!lbus->sbus)
		return -ENODEV;

	for_each_linux_driver(lbus, ldrv) {
		ret = metal_linux_probe_driver(lbus, ldrv);
		/* Clear the error if any driver is available */
		if (!ret)
			error = ret;
	}

	if (error) {
		metal_linux_bus_close(&lbus->bus);
		return error;
	}

	error = metal_linux_register_bus(lbus);
	if (error)
		metal_linux_bus_close(&lbus->bus);

	return error;
}

int metal_linux_bus_init(void)
{
	struct linux_bus *lbus;
	int valid = 0;

	for_each_linux_bus(lbus)
		valid += metal_linux_probe_bus(lbus) ? 0 : 1;

	return valid ? 0 : -ENODEV;
}

void metal_linux_bus_finish(void)
{
	struct linux_bus *lbus;
	struct metal_bus *bus;

	for_each_linux_bus(lbus) {
		if (metal_bus_find(lbus->bus_name, &bus) == 0)
			metal_bus_unregister(bus);
	}
}

int metal_generic_dev_sys_open(struct metal_device *dev)
{
	(void)dev;
	return 0;
}

int metal_linux_get_device_property(struct metal_device *device,
				    const char *property_name,
				    void *output, int len)
{
	int fd = 0;
	int status = 0;
	const int flags = O_RDONLY;
	const int mode = S_IRUSR | S_IRGRP | S_IROTH;
	struct linux_device *ldev = to_linux_device(device);
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/of_node/%s",
			 ldev->sdev->path, property_name);
	fd = open(path, flags, mode);
	if (fd < 0)
		return -errno;
	if (read(fd, output, len) < 0) {
		status = -errno;
		close(fd);
		return status;
	}

	status = close(fd);
	return status < 0 ? -errno : 0;
}
