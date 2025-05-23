
#include <metal/vfio.h>
#include <metal/irq.h>
#include <metal/bus.h>
#include <linux/vfio.h>
#include <metal/device.h>
#include <string.h>
#include <sysfs/libsysfs.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#define MAX_IRQS 1024

struct vfio_priv {
    int container_fd;
    int group_fd;
    int dev_fd;
    char group_path[PATH_MAX];
};

static int metal_vfio_dev_bind(struct linux_device *ldev, struct linux_driver *ldrv)
{
	struct sysfs_attribute *attr;
	int result;
	size_t bdf_len = strlen(ldev->dev_name);

	if (!ldev || !ldrv || !ldev->sdev) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid parameters (ldev=%p, ldrv=%p, sdev=%p)\n", ldev, ldrv, ldev ? ldev->sdev : NULL);
		return -EINVAL;
	}

	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, ldrv->drv_name) == 0) {
		metal_log(METAL_LOG_DEBUG, "VFIO: %s already bound to %s\n", ldev->dev_name, ldrv->drv_name);
		return 0;
	}

	if (ldev->sdev->driver_name[0] && strcmp(ldev->sdev->driver_name, SYSFS_UNKNOWN) != 0) {
		metal_log(METAL_LOG_INFO, "VFIO: %s currently bound to %s - unbinding\n", ldev->dev_name, ldev->sdev->driver_name);

		char group_path[PATH_MAX];
		snprintf(group_path, sizeof(group_path), "%s/iommu_group", ldev->sdev->path);
		if (access(group_path, F_OK) == 0) {
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
			metal_log(METAL_LOG_WARNING, "VFIO: device %s is not in an IOMMU group\n", ldev->dev_name);
		}
		struct linux_bus *cur_bus = to_linux_bus(ldev->device.bus);
		struct sysfs_driver *cur_drv = sysfs_get_bus_driver(cur_bus->sbus, ldev->sdev->driver_name);
		int need_close = 0;

		if (!cur_drv) {
			cur_drv = sysfs_open_driver(cur_bus->bus_name, ldev->sdev->driver_name);
			if (!cur_drv) {
				metal_log(METAL_LOG_ERROR, "VFIO: failed to open current driver %s (errno=%d)\n", ldev->sdev->driver_name, errno);
				return -errno;
			}
			need_close = 1;
		}
		attr = sysfs_get_driver_attr(cur_drv, "unbind");
		if (!attr) {
			metal_log(METAL_LOG_ERROR, "VFIO: driver %s has no unbind attribute\n", ldev->sdev->driver_name);
			if (need_close)
				sysfs_close_driver(cur_drv);
			return -ENOTSUP;
		}

		result = sysfs_write_attribute(attr, ldev->dev_name, bdf_len);
		if (need_close)
			sysfs_close_driver(cur_drv);

		if (result) {
			metal_log(METAL_LOG_ERROR, "VFIO: failed to unbind %s from %s (errno=%d, %s)\n", ldev->dev_name, ldev->sdev->driver_name, errno, strerror(errno));
			return -errno;
		}
	}
	attr = sysfs_get_device_attr(ldev->sdev, "driver_override");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "VFIO: device %s has no driver_override (errno=%d)\n", ldev->dev_name, errno);
		return -errno;
	}

	result = sysfs_write_attribute(attr, ldrv->drv_name, strlen(ldrv->drv_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set override on %s (errno=%d, %s)\n", ldev->dev_name, errno, strerror(errno));
		return -errno;
	}
	ldev->override = attr;
	if (!ldrv->sdrv) {
		metal_log(METAL_LOG_ERROR, "VFIO: driver %s not loaded\n", ldrv->drv_name);
		return -ENODEV;
	}
	attr = sysfs_get_driver_attr(ldrv->sdrv, "bind");
	if (!attr) {
		metal_log(METAL_LOG_ERROR, "VFIO: driver %s has no bind attribute\n", ldrv->drv_name);
		return -ENOTSUP;
	}

	result = sysfs_write_attribute(attr, ldev->dev_name, strlen(ldev->dev_name));
	if (result) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to bind %s to %s (errno=%d, %s)\n", ldev->dev_name, ldrv->drv_name, errno, strerror(errno));
		return -errno;
	}

	return 0;
}

static int metal_vfio_fixup_group(struct linux_device *ldev, struct linux_driver *ldrv) {
    char dir[PATH_MAX] = {0};
    struct dlist *list;
    char *peer_name;

    snprintf(dir, sizeof(dir), "%s/iommu_group/devices", ldev->sdev->path);
    list = sysfs_open_link_list(dir);
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

        if (!strcmp(peer->driver_name, ldrv->drv_name) || !strcmp(peer->driver_name, SYSFS_UNKNOWN)) {
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

int metal_vfio_dev_open(struct linux_bus *lbus, struct linux_device *ldev)
{
	char                path[PATH_MAX];
	char                linkbuf[PATH_MAX];
	ssize_t             linklen;
	int                 ret;
	struct linux_driver *ldrv = ldev->ldrv;

	if (!lbus || !ldev || !ldrv) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid parameters (lbus=%p, ldev=%p, ldrv=%p)\n", lbus, ldev, ldrv);
		return -EINVAL;
	}

	ldev->dev_name[sizeof(ldev->dev_name)-1] = '\0';
	ldev->fd               = -1;
	ldev->device.irq_info  = (void *)-1;
	ldev->device.priv      = NULL;
	metal_log(METAL_LOG_DEBUG, "VFIO: starting initialization for device %s on bus %s\n", ldev->dev_name, lbus->bus_name);
	struct vfio_priv    *priv = calloc(1, sizeof(*priv));
	if (!priv) {
		metal_log(METAL_LOG_ERROR, "VFIO: cannot allocate memory for %s:%s\n",
			lbus->bus_name, ldev->dev_name);
		return -ENOMEM;
	}
	ldev->device.priv = priv;
	priv->container_fd = -1;
	priv->group_fd = -1;
	priv->dev_fd = -1;
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
		metal_log(METAL_LOG_DEBUG, "VFIO: cannot bind device %s to driver %s - error: %d (%s)\n",
		            ldev->dev_name, ldrv->drv_name, errno, strerror(errno));
		return ret;
	}

	ret = metal_vfio_fixup_group(ldev, ldrv);
	if (ret) {
		metal_log(METAL_LOG_DEBUG, "VFIO: error while binding device peer %s to driver %s - error: %d (%s)\n",
		            ldev->dev_name, ldrv->drv_name, errno, strerror(errno));
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
	snprintf(ldev->cls_path, sizeof(ldev->cls_path), "%s", linkbuf);
	snprintf(priv->group_path, sizeof(priv->group_path), "%s", linkbuf);

	for (int retry = 0; retry < 10 && access(ldev->dev_path, F_OK); ++retry)
		usleep(1000);
	if (access(ldev->dev_path, F_OK)) {
		metal_log(METAL_LOG_ERROR, "VFIO: group node %s not present - error: %d (%s)\n", ldev->dev_path, errno, strerror(errno));
		return -ENODEV;
	}

    priv->container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (priv->container_fd < 0) {
    	int err = -errno;
    	metal_log(METAL_LOG_ERROR, "VFIO: failed to open container (errno=%d) - %s\n", err, strerror(-err));
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
	int api_version = ioctl(priv->container_fd, VFIO_GET_API_VERSION);
	if (api_version != VFIO_API_VERSION) {
		metal_log(METAL_LOG_ERROR, "VFIO: API version mismatch (got %d, expected %d)\n",
			  api_version, VFIO_API_VERSION);
		close(priv->container_fd);
		free(priv);
		return -EINVAL;
	}
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
		metal_log(METAL_LOG_WARNING, "VFIO: WRITE DMA mapping not supported\n"); // notice!
	}

    priv->group_fd = open(ldev->dev_path, O_RDWR);
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
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set container (errno=%d (%s))\n", errno, strerror(errno));
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}
	if (ioctl(priv->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to set IOMMU (errno=%d (%s))\n", errno, strerror(errno));
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
	int reset_ret = ioctl(priv->dev_fd, VFIO_DEVICE_RESET);
	if (reset_ret < 0) {
		int reset_err = errno;
		switch (reset_err) {
		case EINVAL:
			metal_log(METAL_LOG_DEBUG, "VFIO: device %s does not support reset\n",
				  ldev->dev_name);
			break;
		case EBUSY:
			metal_log(METAL_LOG_WARNING, "VFIO: device %s is busy and cannot be reset now\n",
				  ldev->dev_name);
			break;
		case EIO:
			metal_log(METAL_LOG_ERROR, "VFIO: device %s reset failed due to I/O error\n",
				  ldev->dev_name);
			metal_log(METAL_LOG_WARNING, "VFIO: continuing with potentially unstable device %s after reset failure\n",
				  ldev->dev_name);
			break;
		case ENODEV:
			metal_log(METAL_LOG_ERROR, "VFIO: device %s no longer exists\n",
				  ldev->dev_name);
			goto err_close_dev;
		default:
			metal_log(METAL_LOG_WARNING, "VFIO: device %s reset failed (errno=%d)\n",
				  ldev->dev_name, reset_err);
		}
	} else {
		metal_log(METAL_LOG_DEBUG, "VFIO: device %s reset completed successfully\n",
			  ldev->dev_name);

		struct vfio_device_info dinfo = { .argsz = sizeof(dinfo) };
		if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &dinfo) == 0) {
			metal_log(METAL_LOG_DEBUG, "VFIO: device %s info after reset - flags:0x%x regions:%d irqs:%d\n",
				  ldev->dev_name, dinfo.flags, dinfo.num_regions, dinfo.num_irqs);
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
			metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info after reset (errno=%d (%s))\n",
				  errno);
			goto err_close_dev;
		}
	}

	struct vfio_device_info dinfo = { .argsz = sizeof(dinfo) };
	if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &dinfo)) {
		metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info for %s (errno=%d (%s))\n",
			  ldev->dev_name, errno);
		close(priv->dev_fd);
		close(priv->group_fd);
		close(priv->container_fd);
		return -errno;
	}

    for (uint32_t i = 0; i < dinfo.num_regions &&
                    ldev->device.num_regions < METAL_MAX_DEVICE_REGIONS; ++i) {
        struct vfio_region_info reg = {
            .argsz = sizeof(reg),
            .index = i
        };
        if (ioctl(priv->dev_fd, VFIO_DEVICE_GET_REGION_INFO, &reg)) {
            int region_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: failed to get region %u info for %s (errno=%d, %s)\n",
                      i, ldev->dev_name, region_err, strerror(region_err));
            continue;
        }

        if (!(reg.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
            metal_log(METAL_LOG_DEBUG, "VFIO: region %u not mappable (flags=0x%x)\n",
                      i, reg.flags);
            continue;
        }
        if (!reg.size) {
            metal_log(METAL_LOG_WARNING, "VFIO: region %u has zero size\n", i);
            continue;
        }
        void *virt = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED, priv->dev_fd, reg.offset);
        if (virt == MAP_FAILED) { int mmap_err = errno; metal_log(METAL_LOG_ERROR, "VFIO: mmap failed for %s region %u (errno=%d, %s)\n", ldev->dev_name, i, mmap_err, strerror(mmap_err)); continue; }

		metal_phys_addr_t *phys = &ldev->region_phys[ldev->device.num_regions];
		*phys = (metal_phys_addr_t)reg.offset;

		struct metal_io_region *io = &ldev->device.regions[ldev->device.num_regions];
		metal_io_init(io, virt, phys, reg.size, -1, 0, NULL);
		ldev->device.num_regions++;
		metal_log(METAL_LOG_DEBUG,
				"VFIO: region %u mapped virt=%p size=%#llx\n",
				i, virt, (unsigned long long)reg.size);
	}

    int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evtfd < 0) {
        int err = -errno;
        metal_log(METAL_LOG_ERROR, "VFIO: failed to create eventfd for %s (errno=%d)\n",
              ldev->dev_name, err);
        goto err_close_dev;
    }
    metal_log(METAL_LOG_DEBUG, "VFIO: created eventfd %d\n", evtfd);
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

    metal_log(METAL_LOG_INFO, "VFIO: %s initialised (regions=%u)\n", ldev->dev_name);
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

void metal_vfio_dev_close(struct linux_bus *lbus,
				struct linux_device *ldev)
{
	(void)lbus;
	struct vfio_priv    *priv = ldev->device.priv;

	if (!priv) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s - no private data\n", ldev->dev_name);
		return;
	}
	metal_log(METAL_LOG_DEBUG, "VFIO: closing device %s (regions=%u)\n", ldev->dev_name, ldev->device.num_regions);
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
    if (ldev->device.irq_info != (void *)-1 && ldev->device.irq_info) {
        int evtfd = (int)(intptr_t)ldev->device.irq_info;
        if (priv->dev_fd >= 0) {
            struct vfio_irq_set irq_set = {
                .argsz = sizeof(irq_set),
                .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                .index = VFIO_PCI_INTX_IRQ_INDEX,
                .start = 0,
                .count = 0,
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
    if (ldev->override) {
        metal_log(METAL_LOG_DEBUG, "VFIO: resetting driver override\n");
        if (sysfs_write_attribute(ldev->override, "", 1) < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: failed to reset driver override\n");
        }
        ldev->override = NULL;
    }
    if (ldev->sdev) {
        metal_log(METAL_LOG_DEBUG, "VFIO: closing sysfs device\n");
        sysfs_close_device(ldev->sdev);
        ldev->sdev = NULL;
    }
    if (priv) {

        if (priv->dev_fd >= 0) {
            metal_log(METAL_LOG_DEBUG, "VFIO: closing device fd %d\n", priv->dev_fd);
            if (close(priv->dev_fd) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to close device fd %d (errno=%d)\n",
                          priv->dev_fd, errno);
            }
            priv->dev_fd = -1;
        }
        if (priv->group_fd >= 0) {
            metal_log(METAL_LOG_DEBUG, "VFIO: closing group fd %d\n", priv->group_fd);
            if (close(priv->group_fd) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to close group fd %d (errno=%d)\n",
                          priv->group_fd, errno);
            }
            priv->group_fd = -1;
        }
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

int metal_vfio_dev_dma_map(struct linux_bus *lbus,
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
	if (!(dir & (VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE))) {
		metal_log(METAL_LOG_ERROR, "VFIO: invalid DMA direction flags 0x%x (must include READ and/or WRITE)\n", dir);
		return -EINVAL;
	}
	if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		metal_log(METAL_LOG_ERROR, "VFIO: TYPE1 IOMMU not supported by host\n");
		if (!ioctl(priv->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU)) {
			metal_log(METAL_LOG_ERROR, "VFIO: TYPE1v2 IOMMU also not supported\n");
		}
		return -EOPNOTSUPP;
	}
	char group_path[PATH_MAX];
	snprintf(group_path, sizeof(group_path), "/sys/kernel/iommu_groups/%d",
			atoi(strrchr(priv->group_path, '/') + 1));
	if (access(group_path, F_OK) < 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: IOMMU group %s not accessible (errno=%d)\n",
			  priv->group_path, errno);
		return -ENODEV;
	}
	memset(&device_info, 0, sizeof(device_info));
	device_info.argsz = sizeof(device_info);

	ret = ioctl(priv->dev_fd, VFIO_DEVICE_GET_INFO, &device_info);
	if (ret) {
		int err = errno;
		metal_log(METAL_LOG_ERROR, "VFIO: failed to get device info for %s (errno=%d) - %s\n",
					  ldev->dev_name, err, strerror(err));
		return -err;
	}
	for (i = 0; i < nents_in; i++) {
		if (!sg_in[i].virt || !sg_in[i].len) {
			metal_log(METAL_LOG_ERROR, "VFIO: invalid sg entry %d (virt=%p, len=%zu)\n",
				  i, sg_in[i].virt, sg_in[i].len);
			return -EINVAL;
		}
		if ((uintptr_t)sg_in[i].virt & (getpagesize() - 1)) {
			metal_log(METAL_LOG_ERROR, "VFIO: unaligned sg entry %d (virt=%p)\n",
				  i, sg_in[i].virt);
			return -EINVAL;
		}
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
    if (sg_out != sg_in) {
        memcpy(sg_out, sg_in, nents_in * sizeof(struct metal_sg));
    }
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
    for (i = 0; i < nents_in; i++) {
        memset(&dma_map, 0, sizeof(dma_map));
        dma_map.argsz = sizeof(dma_map);
        dma_map.vaddr = (uint64_t)(uintptr_t)sg_in[i].virt;
        dma_map.size = sg_in[i].len;
        dma_map.iova = (uint64_t)(uintptr_t)sg_in[i].virt;
        dma_map.flags = dir;

        ret = ioctl(priv->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
        if (ret) {
            int map_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: failed to map DMA for sg %d (errno=%d)\n",
                     i, map_err);
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


    metal_log(METAL_LOG_DEBUG, "VFIO: successfully mapped %d DMA regions for device %s\n",
         nents_in, ldev->dev_name);
    return nents_in;
}

void metal_vfio_dev_irq_ack(struct linux_bus *lbus,
                                   struct linux_device *ldev,
                                   int irq)
{
    (void)lbus;
    struct vfio_priv *priv = ldev->device.priv;

    if (!priv || priv->dev_fd < 0) {
        metal_log(METAL_LOG_ERROR,
                 "VFIO: %s - invalid device state for IRQ ack (priv=%p, fd=%d)\n",
                 ldev->dev_name, priv, priv ? priv->dev_fd : -1);
        return;
    }


    if (!priv || priv->dev_fd < 0) {
        metal_log(METAL_LOG_ERROR,
                 "VFIO: %s - invalid device state for IRQ ack (priv=%p, fd=%d)\n",
                 ldev->dev_name, priv, priv ? priv->dev_fd : -1);
        return;
    }

    metal_log(METAL_LOG_DEBUG, "VFIO: %s - acknowledging IRQ %d\n",
             ldev->dev_name, irq);
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
    metal_log(METAL_LOG_DEBUG, "VFIO: %s IRQ %d flags=0x%x count=%d\n",
             ldev->dev_name, irq, irq_info.flags, irq_info.count);
    if (!(irq_info.flags & VFIO_IRQ_INFO_EVENTFD)) {
        metal_log(METAL_LOG_ERROR, "VFIO: eventfd not supported for IRQ type %d (flags=0x%x)\n",
                 irq, irq_info.flags);
        return;
    }
    if (irq == VFIO_PCI_INTX_IRQ_INDEX) {
        int evtfd = (int)(intptr_t)ldev->device.irq_info;
        if (evtfd < 0) {
            metal_log(METAL_LOG_ERROR, "VFIO: invalid eventfd %d for INTx\n", evtfd);
            return;
        }
        uint64_t counter;
        if (read(evtfd, &counter, sizeof(counter)) < 0) {
            int read_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: read eventfd %d failed (errno=%d)\n",
                     evtfd, read_err);
            struct vfio_irq_set reset = {
                .argsz = sizeof(reset),
                .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                .index = VFIO_PCI_INTX_IRQ_INDEX,
                .start = 0,
                .count = 0,
            };
            if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &reset) < 0) {
                metal_log(METAL_LOG_ERROR, "VFIO: failed to reset INTx after read error\n");
            }
            return;
        }
        struct vfio_irq_set unmask = { .argsz = sizeof(unmask),
            .flags = VFIO_IRQ_SET_ACTION_UNMASK, .index = VFIO_PCI_INTX_IRQ_INDEX, .start = 0, .count = 1,
        };

        if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &unmask) < 0) {
            int unmask_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: INTx unmask failed (errno=%d (%s))\n",
                     unmask_err);
            if (counter > 0) {
                if (write(evtfd, &counter, sizeof(counter)) < 0) {
                    metal_log(METAL_LOG_ERROR, "VFIO: failed to restore eventfd counter\n");
                }
            }
        }
    }

    else if (irq == VFIO_PCI_MSI_IRQ_INDEX ||
             irq == VFIO_PCI_MSIX_IRQ_INDEX) {

        struct vfio_irq_set trigger = {
            .argsz = sizeof(trigger),
            .flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE,
            .index = irq,
            .start = 0,
            .count = 1,
        };

        if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &trigger) < 0) {
            int trigger_err = errno;
            metal_log(METAL_LOG_ERROR, "VFIO: MSI/MSI-X trigger failed (errno=%d (%s))\n",
                     trigger_err);
            return;
        }
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
                metal_log(METAL_LOG_ERROR, "VFIO: MSI-X restore failed (errno=%d (%s))\n",
                         restore_err);
                struct vfio_irq_set disable = {
                    .argsz = sizeof(disable),
                    .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                    .index = VFIO_PCI_MSIX_IRQ_INDEX,
                    .start = 0,
                    .count = 0,
                };
                if (ioctl(priv->dev_fd, VFIO_DEVICE_SET_IRQS, &disable) < 0) {
                    metal_log(METAL_LOG_ERROR, "VFIO: failed to disable MSI-X after restore failure (errno=%d)\n", errno);
                }
            }
        }
    } else {
        metal_log(METAL_LOG_WARNING, "VFIO: unsupported IRQ type %d (flags=0x%x)\n",
                 irq, irq_info.flags);
        return;
    }

    metal_log(METAL_LOG_DEBUG, "VFIO: successfully handled IRQ %d for device %s (flags=0x%x)\n",
         irq, ldev->dev_name, irq_info.flags);
}

void metal_vfio_dev_dma_unmap(struct linux_bus *lbus,
				      struct linux_device *ldev,
				      uint32_t dir,
				      struct metal_sg *sg,
				      int nents)
{
	(void)lbus;
	(void)dir;

	struct vfio_priv *priv = ldev->device.priv;
	int                 ret;
	int                 i;

	if (!priv || priv->container_fd < 0) {
		metal_log(METAL_LOG_ERROR, "VFIO: %s - invalid container fd (errno=%d)\n", ldev->dev_name, errno);
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
				 "VFIO: failed to unmap DMA region at addr 0x%llx (errno=%d (%s))\n",
				 (unsigned long long)addr, errno);
			continue;
		}

		metal_log(METAL_LOG_DEBUG, "VFIO: unmapped DMA region at addr 0x%llx, size %zu\n",
			  (unsigned long long)addr, size);
	}

	metal_log(METAL_LOG_DEBUG, "VFIO: %s - DMA unmap completed for %d regions\n",
		ldev->dev_name, nents);
}
