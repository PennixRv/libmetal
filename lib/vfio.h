
#ifndef __METAL_LINUX_VFIO__H__
#define __METAL_LINUX_VFIO__H__

#include <metal/device.h>
#include <metal/irq.h>

#ifdef __cplusplus
extern "C" {
#endif
struct linux_bus;
struct linux_device;
struct linux_driver;

int metal_vfio_dev_open(struct linux_bus *lbus, struct linux_device *ldev);
void metal_vfio_dev_close(struct linux_bus *lbus,
				struct linux_device *ldev);
int metal_vfio_dev_dma_map(struct linux_bus *lbus,
				 struct linux_device *ldev,
				 uint32_t dir,
				 struct metal_sg *sg_in,
				 int nents_in,
				 struct metal_sg *sg_out);
void metal_vfio_dev_irq_ack(struct linux_bus *lbus,
                                   struct linux_device *ldev,
                                   int irq);
void metal_vfio_dev_dma_unmap(struct linux_bus *lbus,
				      struct linux_device *ldev,
				      uint32_t dir,
				      struct metal_sg *sg,
				      int nents);

#ifdef __cplusplus
}
#endif
#endif