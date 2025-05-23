#include <metal/device.h>
#include <metal/uio.h>
#include <metal/irq.h>
#include <metal/bus.h>


int metal_uio_read_map_attr(struct linux_device *ldev,
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

int metal_uio_dev_bind(struct linux_device *ldev,
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

int metal_uio_dev_open(struct linux_bus *lbus, struct linux_device *ldev)
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

void metal_uio_dev_close(struct linux_bus *lbus,
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

void metal_uio_dev_irq_ack(struct linux_bus *lbus,
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

int metal_uio_dev_dma_map(struct linux_bus *lbus,
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

void metal_uio_dev_dma_unmap(struct linux_bus *lbus,
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
