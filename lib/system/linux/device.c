/*
 * Copyright (c) 2015, Xilinx Inc. and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * @file	linux/device.c
 * @brief	Linux libmetal device operations.
 */

#include <metal/device.h>
#include <metal/sys.h>
#include <metal/utilities.h>
#include <metal/irq.h>
#include <linux/vfio.h>

#define MAX_IRQS 1024 /* Maximum number of IRQs supported */

/* VFIO IRQ action types */
#ifndef VFIO_IRQ_SET_ACTION_ACK
#define VFIO_IRQ_SET_ACTION_ACK		(1 << 3)
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sysfs/libsysfs.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define MAX_DRIVERS	64

struct linux_bus;
struct linux_device;

struct linux_driver {
	const char		*drv_name;
	const char		*mod_name;
	const char		*cls_name;
	struct sysfs_driver	*sdrv;
	int			(*dev_open)(struct linux_bus *lbus,
					    struct linux_device *ldev);
	void			(*dev_close)(struct linux_bus *lbus,
					     struct linux_device *ldev);
	void			(*dev_irq_ack)(struct linux_bus *lbus,
					     struct linux_device *ldev,
					     int irq);
	int			(*dev_dma_map)(struct linux_bus *lbus,
						struct linux_device *ldev,
						uint32_t dir,
						struct metal_sg *sg_in,
						int nents_in,
						struct metal_sg *sg_out);
	void			(*dev_dma_unmap)(struct linux_bus *lbus,
						struct linux_device *ldev,
						uint32_t dir,
						struct metal_sg *sg,
						int nents);
};

struct linux_bus {
	struct metal_bus	bus;
	const char		*bus_name;
	struct linux_driver	drivers[MAX_DRIVERS];
	struct sysfs_bus	*sbus;
};

struct linux_device {
	struct metal_device		device;
	char				dev_name[PATH_MAX];
	char				dev_path[PATH_MAX];
	char				cls_path[PATH_MAX];
	metal_phys_addr_t		region_phys[METAL_MAX_DEVICE_REGIONS];
	struct linux_driver		*ldrv;
	struct sysfs_device		*sdev;
	struct sysfs_attribute		*override;
	int				fd;
};

static struct linux_bus *to_linux_bus(struct metal_bus *bus)
{
	return metal_container_of(bus, struct linux_bus, bus);
}

static struct linux_device *to_linux_device(struct metal_device *device)
{
	return metal_container_of(device, struct linux_device, device);
}

static int metal_uio_read_map_attr(struct linux_device *ldev,
				   unsigned int index,
				   const char *name,
				   unsigned long *value)
{
	const char *cls = ldev->cls_path;
	struct sysfs_attribute *attr;
	char path[SYSFS_PATH_MAX];
	int result;

	result = snprintf(path, sizeof(path), "%s/maps/map%u/%s", cls, index, name);
	if (result >= (int)sizeof(path))
		return -EOVERFLOW;
	attr = sysfs_open_attribute(path);
	if (!attr || sysfs_read_attribute(attr) != 0) {
		sysfs_close_attribute(attr);
		return -errno;
	}

	*value = strtoul(attr->value, NULL, 0);

	sysfs_close_attribute(attr);
	return 0;
}

static int metal_uio_dev_bind(struct linux_device *ldev,
			      struct linux_driver *ldrv)
{
	struct sysfs_attribute *attr;
	int result;

	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, ldrv->drv_name) == 0)
		return 0;

	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, SYSFS_UNKNOWN) != 0) {
		metal_log(METAL_LOG_INFO, "device %s in use by driver %s\n",
			  ldev->dev_name, ldev->sdev->driver_name);
		return -EBUSY;
	}

	attr = sysfs_get_device_attr(ldev->sdev, "driver_override");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "device %s has no override\n",
			  ldev->dev_name);
		return -errno;
	}

	result = sysfs_write_attribute(attr, ldrv->drv_name,
				       strlen(ldrv->drv_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "failed to set override on %s\n",
			  ldev->dev_name);
		return -errno;
	}
	ldev->override = attr;

	attr = sysfs_get_driver_attr(ldrv->sdrv, "bind");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "driver %s has no bind\n", ldrv->drv_name);
		return -ENOTSUP;
	}

	result = sysfs_write_attribute(attr, ldev->dev_name,
				       strlen(ldev->dev_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "failed to bind %s to %s\n",
			  ldev->dev_name, ldrv->drv_name);
		return -errno;
	}

	metal_log(METAL_LOG_DEBUG, "bound device %s to driver %s\n",
		  ldev->dev_name, ldrv->drv_name);

	return 0;
}

static int metal_uio_dev_open(struct linux_bus *lbus, struct linux_device *ldev)
{
	char *instance, path[SYSFS_PATH_MAX];
	struct linux_driver *ldrv = ldev->ldrv;
	unsigned long *phys, offset = 0, size = 0;
	struct metal_io_region *io;
	struct dlist *dlist;
	int result, i;
	void *virt;
	int irq_info;


	ldev->fd = -1;
	ldev->device.irq_info = (void *)-1;

	ldev->sdev = sysfs_open_device(lbus->bus_name, ldev->dev_name);
	if (!ldev->sdev) {
		metal_log(METAL_LOG_ERROR, "device %s:%s not found\n",
			  lbus->bus_name, ldev->dev_name);
		return -ENODEV;
	}
	metal_log(METAL_LOG_DEBUG, "opened sysfs device %s:%s\n",
		  lbus->bus_name, ldev->dev_name);

	result = metal_uio_dev_bind(ldev, ldrv);
	if (result)
		return result;

	result = snprintf(path, sizeof(path), "%s/uio", ldev->sdev->path);
	if (result >= (int)sizeof(path))
		return -EOVERFLOW;
	dlist = sysfs_open_directory_list(path);
	if (!dlist) {
		metal_log(METAL_LOG_ERROR, "failed to scan class path %s\n",
			  path);
		return -errno;
	}

	dlist_for_each_data(dlist, instance, char) {
		result = snprintf(ldev->cls_path, sizeof(ldev->cls_path),
				  "%s/%s", path, instance);
		if (result >= (int)sizeof(ldev->cls_path))
			return -EOVERFLOW;
		result = snprintf(ldev->dev_path, sizeof(ldev->dev_path),
				  "/dev/%s", instance);
		if (result >= (int)sizeof(ldev->dev_path))
			return -EOVERFLOW;
		break;
	}
	sysfs_close_list(dlist);

	if (sysfs_path_is_dir(ldev->cls_path) != 0) {
		metal_log(METAL_LOG_ERROR, "invalid device class path %s\n",
			  ldev->cls_path);
		return -ENODEV;
	}

	i = 0;
	do {
		if (!access(ldev->dev_path, F_OK))
			break;
		usleep(10);
		i++;
	} while (i < 1000);
	if (i >= 1000) {
		metal_log(METAL_LOG_ERROR, "failed to open file %s, timeout.\n",
			  ldev->dev_path);
		return -ENODEV;
	}
	result = metal_open(ldev->dev_path, 0);
	if (result < 0) {
		metal_log(METAL_LOG_ERROR, "failed to open device %s\n",
			  ldev->dev_path, strerror(-result));
		return result;
	}
	ldev->fd = result;

	metal_log(METAL_LOG_DEBUG, "opened %s:%s as %s\n",
		  lbus->bus_name, ldev->dev_name, ldev->dev_path);

	for (i = 0, result = 0; !result && i < METAL_MAX_DEVICE_REGIONS; i++) {
		phys = &ldev->region_phys[ldev->device.num_regions];
		result = (result ? result :
			 metal_uio_read_map_attr(ldev, i, "offset", &offset));
		result = (result ? result :
			 metal_uio_read_map_attr(ldev, i, "addr", phys));
		result = (result ? result :
			 metal_uio_read_map_attr(ldev, i, "size", &size));
		result = (result ? result :
			 metal_map(ldev->fd, i * getpagesize(), size, 0, 0, &virt));
		if (!result) {
			io = &ldev->device.regions[ldev->device.num_regions];
			metal_io_init(io, virt, phys, size, -1, 0, NULL);
			ldev->device.num_regions++;
		}
	}

	irq_info = 1;
	if (write(ldev->fd, &irq_info, sizeof(irq_info)) <= 0) {
		metal_log(METAL_LOG_INFO,
			  "%s: No IRQ for device %s.\n",
			  __func__, ldev->dev_name);
		ldev->device.irq_num =  0;
		ldev->device.irq_info = (void *)-1;
	} else {
		ldev->device.irq_num =  1;
		ldev->device.irq_info = (void *)(intptr_t)ldev->fd;
		metal_linux_irq_register_dev(&ldev->device, ldev->fd);
	}

	return 0;
}

static void metal_uio_dev_close(struct linux_bus *lbus,
				struct linux_device *ldev)
{
	(void)lbus;
	unsigned int i;

	for (i = 0; i < ldev->device.num_regions; i++) {
		metal_unmap(ldev->device.regions[i].virt,
			    ldev->device.regions[i].size);
	}
	if (ldev->override) {
		sysfs_write_attribute(ldev->override, "", 1);
		ldev->override = NULL;
	}
	if (ldev->sdev) {
		sysfs_close_device(ldev->sdev);
		ldev->sdev = NULL;
	}
	if (ldev->fd >= 0) {
		close(ldev->fd);
	}
}

static void metal_uio_dev_irq_ack(struct linux_bus *lbus,
				 struct linux_device *ldev,
				 int irq)
{
	(void)lbus;
	(void)irq;
	int irq_info = 1;
	unsigned int val;
	int ret;

	ret = read(ldev->fd, (void *)&val, sizeof(val));
	if (ret < 0) {
		metal_log(METAL_LOG_ERROR, "%s, read uio irq fd %d failed: %d.\n",
						__func__, ldev->fd, ret);
		return;
	}
	ret = write(ldev->fd, &irq_info, sizeof(irq_info));
	if (ret < 0) {
		metal_log(METAL_LOG_ERROR, "%s, write uio irq fd %d failed: %d.\n",
						__func__, ldev->fd, errno);
	}
}

static int metal_uio_dev_dma_map(struct linux_bus *lbus,
				 struct linux_device *ldev,
				 uint32_t dir,
				 struct metal_sg *sg_in,
				 int nents_in,
				 struct metal_sg *sg_out)
{
	int i, j;
	void *vaddr_sg_lo, *vaddr_sg_hi, *vaddr_lo, *vaddr_hi;
	struct metal_io_region *io;

	(void)lbus;
	(void)dir;

	/* Check if the the input virt address is MMIO address */
	for (i = 0; i < nents_in; i++) {
		vaddr_sg_lo = sg_in[i].virt;
		vaddr_sg_hi = vaddr_sg_lo + sg_in[i].len;
		for (j = 0, io = ldev->device.regions;
		     j < (int)ldev->device.num_regions; j++, io++) {
			vaddr_lo = io->virt;
			vaddr_hi = vaddr_lo + io->size;
			if (vaddr_sg_lo >= vaddr_lo &&
			    vaddr_sg_hi <= vaddr_hi) {
				break;
			}
		}
		if (j == (int)ldev->device.num_regions) {
			metal_log(METAL_LOG_WARNING,
			  "%s,%s: input address isn't MMIO addr: 0x%x,%d.\n",
			__func__, ldev->dev_name, vaddr_sg_lo, sg_in[i].len);
			return -EINVAL;
		}
	}
	if (sg_out != sg_in)
		memcpy(sg_out, sg_in, nents_in*(sizeof(struct metal_sg)));
	return nents_in;
}

static void metal_uio_dev_dma_unmap(struct linux_bus *lbus,
				    struct linux_device *ldev,
				    uint32_t dir,
				    struct metal_sg *sg,
				    int nents)
{
	(void) lbus;
	(void) ldev;
	(void) dir;
	(void) sg;
	(void) nents;
}

struct vfio_priv {
    int container_fd;   /* /dev/vfio/vfio                */
    int group_fd;       /* /dev/vfio/<gid>               */
    int dev_fd;         /* VFIO_GROUP_GET_DEVICE_FD      */
    char group_path[PATH_MAX]; /* Path to IOMMU group */
};

static int metal_vfio_dev_bind(struct linux_device *ldev,
				struct linux_driver *ldrv)
{
	struct sysfs_attribute *attr;
	int result;
	size_t bdf_len = strlen(ldev->dev_name);

	/* Check if already bound to the correct driver */
	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, ldrv->drv_name) == 0) {
		metal_log(METAL_LOG_DEBUG, "VFIO: %s already bound to %s\n",
			  ldev->dev_name, ldrv->drv_name);
		return 0;
	}

	/* If bound to another driver, unbind it first */
	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, SYSFS_UNKNOWN) != 0) {
		metal_log(METAL_LOG_DEBUG, "VFIO: %s currently bound to %s - unbinding\n",
			  ldev->dev_name, ldev->sdev->driver_name);
		metal_log(METAL_LOG_DEBUG, "VFIO: checking device group for %s\n",
			  ldev->dev_name);

		/* Check if device is in a group with other devices */
		char group_path[PATH_MAX];
		snprintf(group_path, sizeof(group_path), "%s/iommu_group", ldev->sdev->path);
		if (access(group_path, F_OK) == 0) {
			metal_log(METAL_LOG_DEBUG, "VFIO: device %s is in an IOMMU group at %s\n",
				  ldev->dev_name, group_path);

			/* Get group ID for more detailed logging */
			char linkbuf[SYSFS_PATH_MAX];
			ssize_t linklen = readlink(group_path, linkbuf, sizeof(linkbuf)-1);
			if (linklen > 0) {
				linkbuf[linklen] = '\0';
				char *group_id = strrchr(linkbuf, '/');
				if (group_id) {
					metal_log(METAL_LOG_DEBUG, "VFIO: device %s is in IOMMU group %s\n",
						  ldev->dev_name, group_id+1);
				}
			}
		} else {
			metal_log(METAL_LOG_WARNING, "VFIO: device %s is not in an IOMMU group - VFIO may not work properly\n",
				  ldev->dev_name);
		}

		struct linux_bus *cur_bus = to_linux_bus(ldev->device.bus);
		struct sysfs_driver *cur_drv = sysfs_get_bus_driver(cur_bus->sbus, ldev->sdev->driver_name);
		int need_close = 0;

		if (!cur_drv) {
			cur_drv = sysfs_open_driver(cur_bus->bus_name, ldev->sdev->driver_name);
			if (!cur_drv) {
				metal_log(METAL_LOG_ERROR, "failed to open current driver %s\n",
					  ldev->sdev->driver_name);
				return -errno;
			}
			need_close = 1;
		}

		attr = sysfs_get_driver_attr(cur_drv, "unbind");
		if (!attr) {
			metal_log(METAL_LOG_ERROR, "driver %s has no unbind\n",
				  ldev->sdev->driver_name);
			if (need_close)
				sysfs_close_driver(cur_drv);
			return -ENOTSUP;
		}

		result = sysfs_write_attribute(attr, ldev->dev_name, bdf_len);
		if (need_close)
			sysfs_close_driver(cur_drv);

		if (result) {
			metal_log(METAL_LOG_ERROR, "failed to unbind %s from %s\n",
				  ldev->dev_name, ldev->sdev->driver_name);
			return -errno;
		}

		/* Wait for unbind to complete */
		usleep(10000);
	}

	/* Set driver override */
	attr = sysfs_get_device_attr(ldev->sdev, "driver_override");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "VFIO: device %s has no override\n",
			  ldev->dev_name);
		return -errno;
	}

	result = sysfs_write_attribute(attr, ldrv->drv_name,
				      strlen(ldrv->drv_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set override on %s\n",
			  ldev->dev_name);
		return -errno;
	}
	ldev->override = attr;

	/* Bind to new driver */
	attr = sysfs_get_driver_attr(ldrv->sdrv, "bind");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "VFIO: driver %s has no bind\n", ldrv->drv_name);
		return -ENOTSUP;
	}

	result = sysfs_write_attribute(attr, ldev->dev_name,
				      strlen(ldev->dev_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to bind %s to %s\n",
			  ldev->dev_name, ldrv->drv_name);
		return -errno;
	}

	/* Wait for bind to complete - increased from 10ms to 100ms for slower systems */
	usleep(100000);

	metal_log(METAL_LOG_DEBUG, "VFIO: successfully bound device %s to driver %s\n",
		  ldev->dev_name, ldrv->drv_name);
	return 0;
}

static int metal_vfio_fixup_group(struct linux_device *ldev,
                                  struct linux_driver *ldrv)
{
    char dir[PATH_MAX];
    struct dlist *list;
    char *peer_name;

    snprintf(dir, sizeof(dir), "%s/iommu_group/devices", ldev->sdev->path);
    list = sysfs_open_directory_list(dir);
    if (!list)
        return -errno;

    dlist_for_each_data(list, peer_name, char) {

        if (!strcmp(peer_name, ldev->dev_name))
            continue;

		struct linux_bus *cur_bus = to_linux_bus(ldev->device.bus);
        struct sysfs_device *peer = sysfs_open_device(cur_bus->bus_name, peer_name);
        if (!peer) {
            sysfs_close_list(list);
            return -errno;
        }

        struct sysfs_attribute *class_attr = sysfs_get_device_attr(peer, "class");
        unsigned class_code = 0;
        if (class_attr)
            sscanf(class_attr->value, "%x", &class_code);
        if ((class_code >> 16) == 0x06) {
            sysfs_close_device(peer);
            continue;
        }

        if (!strcmp(peer->driver_name, ldrv->drv_name) ||
            !strcmp(peer->driver_name, SYSFS_UNKNOWN)) {
            sysfs_close_device(peer);
            continue;
        }

        struct linux_device pldev = { 0 };
        strncpy(pldev.dev_name, peer_name, sizeof(pldev.dev_name) - 1);
        pldev.sdev = peer;

        int r = metal_vfio_dev_bind(&pldev, ldrv);
        sysfs_close_device(peer);
        if (r) {
            sysfs_close_list(list);
            metal_log(METAL_LOG_ERROR,
                      "vfio: failed to bind peer %s (err=%d)\n",
                      peer_name, r);
            return r;
        }
        metal_log(METAL_LOG_DEBUG,
                  "vfio: peer %s bound to vfio-pci\n", peer_name);
    }

    sysfs_close_list(list);
    return 0;
}

 /**
 * metal_vfio_dev_open - Open and initialize a VFIO device
 * @lbus: Linux bus structure
 * @ldev: Linux device structure
 *
 * This function:
 * 1. Binds the device to VFIO driver
 * 2. Sets up IOMMU container and group
 * 3. Maps device regions
 * 4. Configures interrupts
 *
 * Returns 0 on success, negative error code on failure.
 */
static int metal_vfio_dev_open(struct linux_bus *lbus, struct linux_device *ldev)
{
	char                path[PATH_MAX];
	char                linkbuf[PATH_MAX];
	ssize_t             linklen;
	int                 ret;
	struct linux_driver *ldrv = ldev->ldrv;
	struct timespec     start, end;
	long                elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Initialize device state with enhanced error checking */
	if (!lbus || !ldev || !ldrv) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid parameters (lbus=%p, ldev=%p, ldrv=%p)\n",
			  lbus, ldev, ldrv);
		return -EINVAL;
	}

	/* Keep original device name */
	ldev->dev_name[sizeof(ldev->dev_name)-1] = '\0'; /* Ensure null termination */
	ldev->fd               = -1;
	ldev->device.irq_info  = (void *)-1;
	ldev->device.priv      = NULL;
	ldev->ldrv             = ldrv;
	ldev->device.bus       = &lbus->bus;

	/* Log device initialization with more details */
	metal_log(METAL_LOG_DEBUG, "VFIO: starting initialization for device %s on bus %s\n",
		  ldev->dev_name, lbus->bus_name);

	/* Allocate and initialize private data */
	struct vfio_priv    *priv = calloc(1, sizeof(*priv));
	if (!priv) {
		metal_log(METAL_LOG_ERROR, "VFIO: cannot allocate memory for %s:%s\n",
			lbus->bus_name, ldev->dev_name);
		return -ENOMEM;
	}
	ldev->device.priv = priv;

	/* Initialize all file descriptors to invalid values */
	priv->container_fd = -1;
	priv->group_fd = -1;
	priv->dev_fd = -1;

	/* Initialize device regions */
	for (int i = 0; i < METAL_MAX_DEVICE_REGIONS; i++) {
		ldev->device.regions[i].virt = NULL;
		ldev->device.regions[i].size = 0;
	}

	ldev->sdev = sysfs_open_device(lbus->bus_name, ldev->dev_name);
	if (!ldev->sdev) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s:%s not found in sysfs (path: %s)\n",
				lbus->bus_name, ldev->dev_name, ldev->sdev ? ldev->sdev->path : "NULL");
		return -ENODEV;
	}
	metal_log(METAL_LOG_DEBUG, "VFIO: sysfs device opened at %s (driver: %s)\n",
				ldev->sdev->path, ldev->sdev->driver_name[0] ? ldev->sdev->driver_name : "NULL");

	struct sysfs_attribute *attr = sysfs_get_device_attr(ldev->sdev, "sriov_numvfs");
	if (attr && sysfs_write_attribute(attr, "0", 1) == 0)
		metal_log(METAL_LOG_DEBUG, "VFIO: SR-IOV disabled for device %s\n", ldev->dev_name);

	ret = metal_vfio_dev_bind(ldev, ldrv);
	if (ret) {
		metal_log(METAL_LOG_DEBUG, "VFIO: cannot bind device %s to driver %s\n", ldev->dev_name, ldrv->drv_name);
		return ret;
	}

	ret = metal_vfio_fixup_group(ldev, ldrv);
	if (ret) {
		metal_log(METAL_LOG_DEBUG, "VFIO: error while binding device peer %s to driver %s\n", ldev->dev_name, ldrv->drv_name);
		return ret;
	}

	snprintf(path, sizeof(path), "%s/iommu_group", ldev->sdev->path);
	linklen = readlink(path, linkbuf, sizeof(linkbuf) - 1);
	if (linklen < 0)
		return -errno;
	linkbuf[linklen] = '\0';

	int gid = atoi(strrchr(linkbuf, '/') + 1);
	if (gid <= 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: bad iommu_group link %s -> %s\n", path, linkbuf);
		return -EINVAL;
	}
	snprintf(ldev->dev_path, sizeof(ldev->dev_path), "/dev/vfio/%d", gid);
	snprintf(ldev->cls_path, sizeof(ldev->cls_path), "%s", linkbuf); /* for debug only */
	snprintf(priv->group_path, sizeof(priv->group_path), "%s", linkbuf);

	for (int retry = 0; retry < 10 && access(ldev->dev_path, F_OK); ++retry)
		usleep(1000);
	if (access(ldev->dev_path, F_OK)) {
		metal_log(METAL_LOG_ERROR, "VFIO: group node %s not present\n", ldev->dev_path);
		return -ENODEV;
	}

    priv->container_fd = metal_open("/dev/vfio/vfio", O_RDWR);
    if (priv->container_fd < 0) {
        int err = -errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to open container (errno=%d)\n", err);
        switch (err) {
        case -EACCES:
            metal_log(METAL_LOG_ERROR, "VFIO: permission denied - check if user is in vfio group\n");
            break;
        case -ENOENT:
            metal_log(METAL_LOG_ERROR, "VFIO: /dev/vfio/vfio not found - check if vfio module is loaded\n");
            break;
        case -ENODEV:
            metal_log(METAL_LOG_ERROR, "VFIO: no IOMMU support detected\n");
            break;
        default:
            metal_log(METAL_LOG_ERROR, "VFIO: unknown error opening container\n");
            break;
        }
        goto err_free_priv;
    }
    metal_log(METAL_LOG_DEBUG, "VFIO: opened container fd %d\n", priv->container_fd);

	/* Check VFIO API version */
	int api_version = ioctl(priv->container_fd, VFIO_GET_API_VERSION);
	if (api_version != VFIO_API_VERSION) {
		metal_log(METAL_LOG_ERROR, "VFIO: API version mismatch (got %d, expected %d)\n",
			  api_version, VFIO_API_VERSION);
		close(priv->container_fd);
		free(priv);
		return -EINVAL;
	}

	/* Check required VFIO extensions */
	if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		metal_log(METAL_LOG_ERROR, "VFIO: TYPE1 IOMMU not supported by host\n");
		close(priv->container_fd);
		free(priv);
		return -EINVAL;
	}

	if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_DMA_MAP_FLAG_READ)) {
		metal_log(METAL_LOG_WARNING, "VFIO: READ DMA mapping not supported\n");
	}

	if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_DMA_MAP_FLAG_WRITE)) {
		metal_log(METAL_LOG_WARNING, "VFIO: WRITE DMA mapping not supported\n");
	}

    priv->group_fd = metal_open(ldev->dev_path, O_RDWR);
    if (priv->group_fd < 0) {
        int err = -errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to open group %s (errno=%d)\n",
                  ldev->dev_path, err);
        switch (err) {
        case -EACCES:
            metal_log(METAL_LOG_ERROR, "VFIO: permission denied - check if user is in vfio group\n");
            break;
        case -ENOENT:
            metal_log(METAL_LOG_ERROR, "VFIO: group device not found - check if device is bound to vfio-pci\n");
            break;
        case -EBUSY:
            metal_log(METAL_LOG_ERROR, "VFIO: group already in use by another process\n");
            break;
        default:
            metal_log(METAL_LOG_ERROR, "VFIO: unknown error opening group\n");
            break;
        }
        goto err_close_container;
    }
    metal_log(METAL_LOG_DEBUG, "VFIO: opened group fd %d\n", priv->group_fd);

	struct vfio_group_status  gstat = { .argsz = sizeof(gstat) };
	if (ioctl(priv->group_fd, VFIO_GROUP_GET_STATUS, &gstat)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to get group status (errno=%d)\n", errno);
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}
	if (!(gstat.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		metal_log(METAL_LOG_ERROR, "VFIO: group not viable (flags=0x%x)\n",
			  gstat.flags);
		return -EBUSY;
	}

	if (ioctl(priv->group_fd, VFIO_GROUP_SET_CONTAINER, &priv->container_fd)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set container (errno=%d)\n", errno);
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}
	if (ioctl(priv->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set IOMMU (errno=%d)\n", errno);
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}

    priv->dev_fd = ioctl(priv->group_fd, VFIO_GROUP_GET_DEVICE_FD, ldev->dev_name);
    if (priv->dev_fd < 0) {
        int err = -errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to get device fd for %s (errno=%d)\n",
              ldev->dev_name, err);
        switch (err) {
        case -ENODEV:
            metal_log(METAL_LOG_ERROR, "VFIO: device not found - check if device is bound to vfio-pci\n");
            break;
        case -EINVAL:
            metal_log(METAL_LOG_ERROR, "VFIO: invalid device name - check device name format\n");
            break;
        case -EPERM:
            metal_log(METAL_LOG_ERROR, "VFIO: permission denied - check device permissions\n");
            break;
        default:
            metal_log(METAL_LOG_ERROR, "VFIO: unknown error getting device fd\n");
            break;
        }
        goto err_close_group;
    }
    metal_log(METAL_LOG_DEBUG, "VFIO: got device fd %d\n", priv->dev_fd);
	ldev->fd = priv->dev_fd;
	metal_log(METAL_LOG_DEBUG, "VFIO: got device fd %d\n", priv->dev_fd);

	/* Perform device reset with enhanced error handling and timing */
	clock_gettime(CLOCK_MONOTONIC, &start);
	int reset_ret = ioctl(priv->dev_fd, VFIO_DEVICE_RESET);
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
			     (end.tv_nsec - start.tv_nsec);

	if (reset_ret < 0) {
		int reset_err = errno;
		switch (reset_err) {
		case EINVAL:
			metal_log(METAL_LOG_DEBUG, "VFIO: device %s does not support reset (took %ld ns)\n",
				  ldev->dev_name, elapsed_ns);
			break;
		case EBUSY:
			metal_log(METAL_LOG_WARNING, "VFIO: device %s is busy and cannot be reset now (took %ld ns)\n",
				  ldev->dev_name, elapsed_ns);
			break;
		case EIO:
			metal_log(METAL_LOG_ERROR, "VFIO: device %s reset failed due to I/O error (took %ld ns)\n",
				  ldev->dev_name, elapsed_ns);
			metal_log(METAL_LOG_WARNING, "VFIO: continuing with potentially unstable device %s after reset failure\n",
				  ldev->dev_name);
			break;
		case ENODEV:
			metal_log(METAL_LOG_ERROR, "VFIO: device %s no longer exists (took %ld ns)\n",
				  ldev->dev_name, elapsed_ns);
			goto err_close_dev;
		default:
			metal_log(METAL_LOG_WARNING, "VFIO: device %s reset failed (errno=%d, took %ld ns)\n",
				  ldev->dev_name, reset_err, elapsed_ns);
		}
	} else {
		metal_log(METAL_LOG_DEBUG, "VFIO: device %s reset completed successfully in %ld ns\n",
			  ldev->dev_name, elapsed_ns);
		/* Verify device is in known good state after reset */
		struct vfio_device_info dinfo = { .argsz = sizeof(dinfo) };
		if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &dinfo) == 0) {
			metal_log(METAL_LOG_DEBUG, "VFIO: device %s info after reset - flags:0x%x regions:%d irqs:%d\n",
				  ldev->dev_name, dinfo.flags, dinfo.num_regions, dinfo.num_irqs);

			/* Additional state verification */
			if (!(dinfo.flags & VFIO_DEVICE_FLAGS_RESET)) {
				metal_log(METAL_LOG_WARNING, "VFIO: device %s does not report proper reset state (flags=0x%x)\n",
					  ldev->dev_name, dinfo.flags);
			}
			if (dinfo.num_regions == 0) {
				metal_log(METAL_LOG_ERROR, "VFIO: device %s has no regions after reset\n",
					  ldev->dev_name);
				goto err_close_dev;
			}
		} else {
			metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info after reset (errno=%d)\n",
				  errno);
			goto err_close_dev;
		}
	}

	struct vfio_device_info dinfo = { .argsz = sizeof(dinfo) };
	if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &dinfo)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info for %s (errno=%d)\n",
			  ldev->dev_name, errno);
		close(priv->dev_fd);
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}

    /* Process device regions with enhanced checks */
    for (uint32_t i = 0; i < dinfo.num_regions &&
                    ldev->device.num_regions < METAL_MAX_DEVICE_REGIONS; ++i) {
        struct vfio_region_info reg = {
            .argsz = sizeof(reg),
            .index = i
        };

        /* Get region info with error handling */
        if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_REGION_INFO, &reg)) {
            int region_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: failed to get region %u info for %s (errno=%d)\n",
                      i, ldev->dev_name, region_err);
            continue;
        }

        /* Validate region flags and size */
        if (!(reg.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
            metal_log(METAL_LOG_DEBUG, "VFIO: region %u not mappable (flags=0x%x)\n",
                      i, reg.flags);
            continue;
        }
        if (!reg.size) {
            metal_log(METAL_LOG_WARNING, "VFIO: region %u has zero size\n", i);
            continue;
        }

        /* Map region with protection checks */
        void *virt = mmap(NULL, reg.size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, priv->dev_fd, reg.offset);
        if (virt == MAP_FAILED) {
            int mmap_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: mmap failed for %s region %u (errno=%d)\n",
                      ldev->dev_name, i, mmap_err);
            continue;
        }

		metal_phys_addr_t *phys = &ldev->region_phys[ldev->device.num_regions];
		*phys = (metal_phys_addr_t)reg.offset;

		struct metal_io_region *io = &ldev->device.regions[ldev->device.num_regions];
		metal_io_init(io, virt, phys, reg.size, -1, 0, NULL);
		ldev->device.num_regions++;
		metal_log(METAL_LOG_DEBUG,
				"VFIO: region %u mapped virt=%p size=%#llx\n",
				i, virt, (unsigned long long)reg.size);
	}

    /* Setup interrupt handling */
    int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evtfd < 0) {
        int err = -errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to create eventfd for %s (errno=%d)\n",
              ldev->dev_name, err);
        goto err_close_dev;
    }
    metal_log(METAL_LOG_DEBUG, "VFIO: created eventfd %d\n", evtfd);

    /* Check supported IRQ types */
	struct vfio_irq_info      irq_info = {
        .argsz = sizeof(irq_info),
        .index = VFIO_PCI_INTX_IRQ_INDEX,
    };
    if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info) < 0) {
        metal_log(METAL_LOG_ERROR, "VFIO: failed to get IRQ info (errno=%d)\n", errno);
        close(evtfd);
        goto err_close_dev;
    }

    if (!(irq_info.flags & VFIO_IRQ_INFO_EVENTFD)) {
        metal_log(METAL_LOG_ERROR, "VFIO: eventfd not supported for IRQ\n");
        close(evtfd);
        goto err_close_dev;
    }

	struct vfio_irq_set       irq_set = {
        .argsz = sizeof(irq_set) + sizeof(int),
        .flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
        .index = VFIO_PCI_INTX_IRQ_INDEX,
        .start = 0,
        .count = 1,
    };
    *(int *)&irq_set.data = evtfd;

    if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &irq_set) < 0) {
        metal_log(METAL_LOG_ERROR, "VFIO: failed to set IRQ for %s (errno=%d)\n",
              ldev->dev_name, errno);
        close(evtfd);
        goto err_close_dev;
    }

    ldev->device.irq_num  = 1;
    ldev->device.irq_info = (void *)(intptr_t)evtfd;
    if (evtfd > MAX_IRQS) {
        metal_log(METAL_LOG_ERROR, "VFIO: eventfd %d exceeds MAX_IRQS (%d)\n",
                  evtfd, MAX_IRQS);
        close(evtfd);
        goto err_close_dev;
    }
    metal_linux_irq_register_dev(&ldev->device, evtfd);

    metal_log(METAL_LOG_INFO, "VFIO: %s initialised (regions=%u)\n",
            ldev->dev_name);
    return 0;

err_close_dev:
    if (priv->dev_fd >= 0) {
        close(priv->dev_fd);
        priv->dev_fd = -1;
    }
err_close_group:
    if (priv->group_fd >= 0) {
        close(priv->group_fd);
        priv->group_fd = -1;
    }
err_close_container:
    if (priv->container_fd >= 0) {
        close(priv->container_fd);
        priv->container_fd = -1;
    }
err_free_priv:
    if (priv) {
        free(priv);
        ldev->device.priv = NULL;
    }
    return -errno;
}

/**
 * metal_vfio_dev_close - Close and cleanup a VFIO device
 * @lbus: Linux bus structure
 * @ldev: Linux device structure
 *
 * This function:
 * 1. Unmaps all device regions
 * 2. Disables and cleans up interrupts
 * 3. Releases all file descriptors
 * 4. Frees allocated resources
 */
static void metal_vfio_dev_close(struct linux_bus *lbus,
				struct linux_device *ldev)
{
	(void)lbus;
	struct vfio_priv    *priv = ldev->device.priv;

	if (!priv) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s - no private data\n", ldev->dev_name);
		return;
	}

	/* Log device closure for debugging */
	metal_log(METAL_LOG_DEBUG, "VFIO: closing device %s (regions=%u)\n",
		ldev->dev_name, ldev->device.num_regions);

    /* Unmap all device regions with enhanced checks */
    for (unsigned int i = 0; i < ldev->device.num_regions; i++) {
        if (ldev->device.regions[i].virt && ldev->device.regions[i].size) {
            metal_log(METAL_LOG_DEBUG, "VFIO: unmapping region %u at %p (size=%zu)\n",
                      i, ldev->device.regions[i].virt,
                      ldev->device.regions[i].size);
            if (metal_unmap(ldev->device.regions[i].virt,
                          ldev->device.regions[i].size) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to unmap region %u\n", i);
            }
        } else {
            metal_log(METAL_LOG_WARNING, "VFIO: invalid region %u (virt=%p, size=%zu)\n",
                      i, ldev->device.regions[i].virt,
                      ldev->device.regions[i].size);
        }
    }
    ldev->device.num_regions = 0;

    /* Clean up interrupt resources with proper ordering */
    if (ldev->device.irq_info != (void *)-1 && ldev->device.irq_info) {
        int evtfd = (int)(intptr_t)ldev->device.irq_info;

        /* Disable IRQs before closing */
        if (priv->dev_fd >= 0) {
            struct vfio_irq_set irq_set = {
                .argsz = sizeof(irq_set),
                .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                .index = VFIO_PCI_INTX_IRQ_INDEX,
                .start = 0,
                .count = 0, /* Disable all interrupts */
            };
            if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &irq_set) < 0) {
                metal_log(METAL_LOG_WARNING, "VFIO: failed to disable IRQs (errno=%d)\n", errno);
            }
        }

        metal_log(METAL_LOG_DEBUG, "VFIO: closing eventfd %d\n", evtfd);
        if (close(evtfd) < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: failed to close eventfd %d (errno=%d)\n",
                      evtfd, errno);
        }
        ldev->device.irq_info = (void *)-1;
        ldev->device.irq_num = 0;
    }

    /* Reset driver override if set */
    if (ldev->override) {
        metal_log(METAL_LOG_DEBUG, "VFIO: resetting driver override\n");
        if (sysfs_write_attribute(ldev->override, "", 1) < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: failed to reset driver override\n");
        }
        ldev->override = NULL;
    }

    /* Close sysfs device */
    if (ldev->sdev) {
        metal_log(METAL_LOG_DEBUG, "VFIO: closing sysfs device\n");
        sysfs_close_device(ldev->sdev);
        ldev->sdev = NULL;
    }

    /* Clean up VFIO resources in reverse order of creation */
    if (priv) {
        /* Close device fd first */
        if (priv->dev_fd >= 0) {
            metal_log(METAL_LOG_DEBUG, "VFIO: closing device fd %d\n", priv->dev_fd);
            if (close(priv->dev_fd) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to close device fd %d (errno=%d)\n",
                          priv->dev_fd, errno);
            }
            priv->dev_fd = -1;
        }

        /* Then group fd */
        if (priv->group_fd >= 0) {
            metal_log(METAL_LOG_DEBUG, "VFIO: closing group fd %d\n", priv->group_fd);
            if (close(priv->group_fd) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to close group fd %d (errno=%d)\n",
                          priv->group_fd, errno);
            }
            priv->group_fd = -1;
        }

        /* Finally container fd */
        if (priv->container_fd >= 0) {
            metal_log(METAL_LOG_DEBUG, "VFIO: closing container fd %d\n", priv->container_fd);
            if (close(priv->container_fd) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to close container fd %d (errno=%d)\n",
                          priv->container_fd, errno);
            }
            priv->container_fd = -1;
        }

        free(priv);
        ldev->device.priv = NULL;
    }

    /* Close device file descriptor if still open */
    if (ldev->fd >= 0) {
        metal_log(METAL_LOG_DEBUG, "VFIO: closing device fd %d\n", ldev->fd);
        if (close(ldev->fd) < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: failed to close device fd %d (errno=%d)\n",
                      ldev->fd, errno);
        }
        ldev->fd = -1;
    }

    metal_log(METAL_LOG_INFO, "VFIO: %s closed and all resources released\n",
              ldev->dev_name);
}

/**
 * metal_vfio_dev_dma_map - Map DMA regions for a VFIO device
 * @lbus: Linux bus structure
 * @ldev: Linux device structure
 * @dir: DMA direction flags
 * @sg_in: Input scatter-gather list
 * @nents_in: Number of entries in input list
 * @sg_out: Output scatter-gather list
 *
 * Returns number of mapped regions on success, negative error code on failure.
 */
static int metal_vfio_dev_dma_map(struct linux_bus *lbus,
				 struct linux_device *ldev,
				 uint32_t dir,
				 struct metal_sg *sg_in,
				 int nents_in,
				 struct metal_sg *sg_out)
{
	(void) lbus;
	int i, ret;
	void *vaddr_sg_lo, *vaddr_sg_hi, *vaddr_lo, *vaddr_hi;
	struct metal_io_region *io;
	struct vfio_priv *priv = (struct vfio_priv *)ldev->device.priv;
	struct vfio_device_info device_info;
	struct vfio_region_info region_info;
	struct vfio_iommu_type1_dma_map dma_map;
	struct timespec start, end;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Validate input parameters with enhanced checks */
	if (!priv || priv->dev_fd < 0 || priv->container_fd < 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s - invalid device state (priv=%p, dev_fd=%d, container_fd=%d)\n",
			  ldev->dev_name, priv, priv ? priv->dev_fd : -1, priv ? priv->container_fd : -1);
		return -ENODEV;
	}

	if (nents_in <= 0 || nents_in > 1024) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid sg list count %d (must be 1-1024)\n", nents_in);
		return -EINVAL;
	}

	metal_log(METAL_LOG_DEBUG, "VFIO: %s - mapping %d DMA regions (dir=0x%x)\n",
		  ldev->dev_name, nents_in, dir);

	/* Validate DMA direction flags with detailed error messages */
	if (!(dir & (VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE))) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid DMA direction flags 0x%x (must include READ and/or WRITE)\n", dir);
		return -EINVAL;
	}

	/* Check IOMMU type support with detailed error messages */
	if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		metal_log(METAL_LOG_ERROR, "VFIO: TYPE1 IOMMU not supported by host\n");
		if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU)) {
			metal_log(METAL_LOG_ERROR, "VFIO: TYPE1v2 IOMMU also not supported\n");
		}
		return -EOPNOTSUPP;
	}

	/* Check IOMMU group viability */
	char group_path[PATH_MAX];
	snprintf(group_path, sizeof(group_path), "/sys/kernel/iommu_groups/%d",
			atoi(strrchr(priv->group_path, '/') + 1));
	if (access(group_path, F_OK) < 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: IOMMU group %s not accessible (errno=%d)\n",
			  priv->group_path, errno);
		return -ENODEV;
	}

	/* Get device info with detailed error handling */
	memset(&device_info, 0, sizeof(device_info));
	device_info.argsz = sizeof(device_info);

	ret = ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &device_info);
	if (ret) {
		int err = errno;
		metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info for %s (errno=%d)\n",
			  ldev->dev_name, err);
		return -err;
	}

	/* Validate input scatter-gather list */
	for (i = 0; i < nents_in; i++) {
		if (!sg_in[i].virt || !sg_in[i].len) {
			metal_log(METAL_LOG_ERROR, "VFIO: invalid sg entry %d (virt=%p, len=%zu)\n",
				  i, sg_in[i].virt, sg_in[i].len);
			return -EINVAL;
		}

		/* Check for address alignment */
		if ((uintptr_t)sg_in[i].virt & (getpagesize() - 1)) {
			metal_log(METAL_LOG_ERROR, "VFIO: unaligned sg entry %d (virt=%p)\n",
				  i, sg_in[i].virt);
			return -EINVAL;
		}

		/* Validate address range */
		vaddr_sg_lo = sg_in[i].virt;
		vaddr_sg_hi = vaddr_sg_lo + sg_in[i].len;
		for (io = ldev->device.regions; io < &ldev->device.regions[ldev->device.num_regions]; io++) {
			vaddr_lo = io->virt;
			vaddr_hi = vaddr_lo + io->size;
			if (vaddr_sg_lo >= vaddr_lo && vaddr_sg_hi <= vaddr_hi) {
				break;
			}
		}
		if (io == &ldev->device.regions[ldev->device.num_regions]) {
			metal_log(METAL_LOG_ERROR,
				  "VFIO: address 0x%p not in device %s regions\n",
				  vaddr_sg_lo, ldev->dev_name);
			return -EINVAL;
		}
	}

    /* Copy sg list if output is different from input */
    if (sg_out != sg_in) {
        memcpy(sg_out, sg_in, nents_in * sizeof(struct metal_sg));
    }

    /* Check DMA mapping capabilities */
    if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_DMA_MAP_FLAG_READ) &&
        (dir & VFIO_DMA_MAP_FLAG_READ)) {
        metal_log(METAL_LOG_ERROR, "VFIO: READ DMA mapping not supported\n");
        return -EOPNOTSUPP;
    }

    if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_DMA_MAP_FLAG_WRITE) &&
        (dir & VFIO_DMA_MAP_FLAG_WRITE)) {
        metal_log(METAL_LOG_ERROR, "VFIO: WRITE DMA mapping not supported\n");
        return -EOPNOTSUPP;
    }

    /* Perform DMA mapping for each sg entry */
    for (i = 0; i < nents_in; i++) {
        memset(&dma_map, 0, sizeof(dma_map));
        dma_map.argsz = sizeof(dma_map);
        dma_map.vaddr = (uint64_t)(uintptr_t)sg_in[i].virt;
        dma_map.size = sg_in[i].len;
        dma_map.iova = (uint64_t)(uintptr_t)sg_in[i].virt; /* 1:1 mapping */
        dma_map.flags = dir;

        ret = ioctl(priv->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
        if (ret) {
            int map_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: failed to map DMA for sg %d (errno=%d)\n",
                     i, map_err);

		/* Unmap any previously mapped entries */
		for (int k = 0; k < i; k++) {
			struct vfio_iommu_type1_dma_unmap dma_unmap = {
				.argsz = sizeof(dma_unmap),
				.iova = (uint64_t)(uintptr_t)sg_in[k].virt,
				.size = sg_in[k].len
			};
			if (ioctl(priv->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap)) {
				metal_log(METAL_LOG_WARNING,
						 "VFIO: failed to unmap DMA for sg %d during cleanup\n", k);
			}
		}
            return -map_err;
        }
    }

    /* Map device regions */
    for (i = 0; i < (int)device_info.num_regions && ldev->device.num_regions < METAL_MAX_DEVICE_REGIONS; i++) {
        region_info.argsz = sizeof(region_info);
        region_info.index = i;

        ret = ioctl(priv->dev_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info);
        if (ret) {
            metal_log(METAL_LOG_WARNING, "VFIO: failed to get region info for region %d\n", i);
            continue;
        }

        if (!(region_info.flags & VFIO_REGION_INFO_FLAG_MMAP) || region_info.size == 0) {
            continue;
        }

        void *virt = mmap(NULL, region_info.size, PROT_READ | PROT_WRITE, MAP_SHARED, priv->dev_fd, region_info.offset);
        if (virt == MAP_FAILED) {
            metal_log(METAL_LOG_WARNING, "VFIO: failed to mmap region %d (errno=%d)\n", i, errno);
            continue;
        }

        metal_phys_addr_t *phys = &ldev->region_phys[ldev->device.num_regions];
        *phys = (metal_phys_addr_t)region_info.offset;

        struct metal_io_region *io = &ldev->device.regions[ldev->device.num_regions];
        metal_io_init(io, virt, phys, region_info.size, -1, 0, NULL);
        ldev->device.num_regions++;

        metal_log(METAL_LOG_DEBUG, "VFIO: region %d mapped virt=%p size=%#llx\n",
                 i, virt, (unsigned long long)region_info.size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
                (end.tv_nsec - start.tv_nsec);

    metal_log(METAL_LOG_DEBUG, "VFIO: successfully mapped %d DMA regions for device %s in %ld ns\n",
             nents_in, ldev->dev_name, elapsed_ns);
    return nents_in;
}

static void metal_vfio_dev_irq_ack(struct linux_bus *lbus,
                                   struct linux_device *ldev,
                                   int irq)
{
    (void)lbus; /* Unused parameter */
    struct vfio_priv *priv = ldev->device.priv;

    if (!priv || priv->dev_fd < 0) {
        metal_log(METAL_LOG_ERROR,
                 "VFIO: %s - invalid device state for IRQ ack (priv=%p, fd=%d)\n",
                 ldev->dev_name, priv, priv ? priv->dev_fd : -1);
        return;
    }
    struct timespec start, end;
    long elapsed_ns;

    clock_gettime(CLOCK_MONOTONIC, &start);

    if (!priv || priv->dev_fd < 0) {
        metal_log(METAL_LOG_ERROR,
                 "VFIO: %s - invalid device state for IRQ ack (priv=%p, fd=%d)\n",
                 ldev->dev_name, priv, priv ? priv->dev_fd : -1);
        return;
    }

    metal_log(METAL_LOG_DEBUG, "VFIO: %s - acknowledging IRQ %d\n",
             ldev->dev_name, irq);

    /* Get IRQ info with detailed error handling */
    struct vfio_irq_info irq_info = {
        .argsz = sizeof(irq_info),
        .index = irq,
    };
    if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info) < 0) {
        int info_err = errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to get IRQ %d info for device %s (errno=%d %s)\n",
                  irq, ldev->dev_name, info_err, strerror(info_err));
        return;
    }

    /* Log IRQ capabilities for debugging */
    metal_log(METAL_LOG_DEBUG, "VFIO: %s IRQ %d flags=0x%x count=%d\n",
             ldev->dev_name, irq, irq_info.flags, irq_info.count);

    /* Validate IRQ flags with detailed checks */
    if (!(irq_info.flags & VFIO_IRQ_INFO_EVENTFD)) {
        metal_log(METAL_LOG_ERROR, "VFIO: eventfd not supported for IRQ type %d (flags=0x%x)\n",
                 irq, irq_info.flags);
        return;
    }

    /* Handle INTx interrupts with enhanced error recovery */
    if (irq == VFIO_PCI_INTX_IRQ_INDEX) {
        int evtfd = (int)(intptr_t)ldev->device.irq_info;
        if (evtfd < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: invalid eventfd %d for INTx\n", evtfd);
            return;
        }

        /* Read eventfd to clear pending interrupt with error handling */
        uint64_t counter;
        if (read(evtfd, &counter, sizeof(counter)) < 0) {
            int read_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: read eventfd %d failed (errno=%d)\n",
                     evtfd, read_err);

            /* Attempt to reset the interrupt state */
            struct vfio_irq_set reset = {
                .argsz = sizeof(reset),
                .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                .index = VFIO_PCI_INTX_IRQ_INDEX,
                .start = 0,
                .count = 0, /* Disable interrupts */
            };
            if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &reset) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to reset INTx after read error\n");
            }
            return;
        }

        /* Unmask the interrupt with detailed error handling */
        struct vfio_irq_set unmask = {
            .argsz = sizeof(unmask),
            .flags = VFIO_IRQ_SET_ACTION_UNMASK,
            .index = VFIO_PCI_INTX_IRQ_INDEX,
            .start = 0,
            .count = 1,
        };

        if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &unmask) < 0) {
            int unmask_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: INTx unmask failed (errno=%d)\n",
                     unmask_err);

            /* Attempt to restore previous state */
            if (counter > 0) {
                if (write(evtfd, &counter, sizeof(counter)) < 0) {
                    metal_log(METAL_LOG_ERROR, "VFIO: failed to restore eventfd counter\n");
                }
            }
        }
    }
    /* Handle MSI/MSI-X interrupts with enhanced error recovery */
    else if (irq == VFIO_PCI_MSI_IRQ_INDEX ||
             irq == VFIO_PCI_MSIX_IRQ_INDEX) {
        /* For MSI/MSI-X, trigger the interrupt with detailed error handling */
        struct vfio_irq_set trigger = {
            .argsz = sizeof(trigger),
            .flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE,
            .index = irq,
            .start = 0,
            .count = 1,
        };

        if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &trigger) < 0) {
            int trigger_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: MSI/MSI-X trigger failed (errno=%d)\n",
                     trigger_err);
            return;
        }

        /* For MSI-X, check if we need to restore the vector with detailed error handling */
        if (irq == VFIO_PCI_MSIX_IRQ_INDEX) {
            struct vfio_irq_set restore = {
                .argsz = sizeof(restore),
                .flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE,
                .index = VFIO_PCI_MSIX_IRQ_INDEX,
                .start = 0,
                .count = 1,
            };

            if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &restore) < 0) {
                int restore_err = errno;
                metal_log(METAL_LOG_ERROR, "VFIO: MSI-X restore failed (errno=%d)\n",
                         restore_err);

                /* Attempt to disable the interrupt completely */
                struct vfio_irq_set disable = {
                    .argsz = sizeof(disable),
                    .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                    .index = VFIO_PCI_MSIX_IRQ_INDEX,
                    .start = 0,
                    .count = 0,
                };
                if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &disable) < 0) {
                    metal_log(METAL_LOG_ERROR, "VFIO: failed to disable MSI-X after restore failure\n");
                }
            }
        }
    } else {
        metal_log(METAL_LOG_WARNING, "VFIO: unsupported IRQ type %d (flags=0x%x)\n",
                 irq, irq_info.flags);
        return;
    }

    /* Log successful IRQ handling with more details */
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
                (end.tv_nsec - start.tv_nsec);

    metal_log(METAL_LOG_DEBUG, "VFIO: successfully handled IRQ %d for device %s (flags=0x%x) in %ld ns\n",
             irq, ldev->dev_name, irq_info.flags, elapsed_ns);
}

/**
 * metal_vfio_dev_dma_map - Map DMA regions for a VFIO device
 * @lbus: Linux bus structure
 * @ldev: Linux device structure
 * @dir: DMA direction flags
 * @sg_in: Input scatter-gather list
 * @nents_in: Number of entries in input list
 * @sg_out: Output scatter-gather list
 *
 * Returns number of mapped regions on success, negative error code on failure.
 */
static void metal_vfio_dev_dma_unmap(struct linux_bus *lbus,
				      struct linux_device *ldev,
				      uint32_t dir,
				      struct metal_sg *sg,
				      int nents)
{
	(void)lbus; /* Unused parameter */
	(void)dir; /* Unused parameter */

	struct vfio_priv *priv = ldev->device.priv;
	int                 ret;
	int                 i;
	struct timespec start, end;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (!priv || priv->container_fd < 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s - invalid container fd\n", ldev->dev_name);
		return;
	}

	for (i = 0; i < nents; i++) {
		metal_phys_addr_t addr = sg[i].io->physmap[i];
		size_t size = sg[i].len;

		struct vfio_iommu_type1_dma_unmap dma_unmap = {
			.argsz = sizeof(dma_unmap),
			.iova = (uint64_t)addr,
			.size = size
		};

		ret = ioctl(priv->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
		if (ret) {
			metal_log(METAL_LOG_ERROR,
				 "VFIO: failed to unmap DMA region at addr 0x%llx (errno=%d)\n",
				 (unsigned long long)addr, errno);
			continue;
		}

		metal_log(METAL_LOG_DEBUG, "VFIO: unmapped DMA region at addr 0x%llx, size %zu\n",
			  (unsigned long long)addr, size);
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
				(end.tv_nsec - start.tv_nsec);
	metal_log(METAL_LOG_DEBUG, "VFIO: %s - DMA unmap completed in %ld ns for %d regions\n",
			ldev->dev_name, elapsed_ns, nents);
}

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
			{
				.drv_name  = "uio_pci_generic",
				.mod_name  = "uio_pci_generic",
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
			if (strcmp(ldrv->drv_name, sdev->driver_name) == 0) {
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
