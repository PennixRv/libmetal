#include <metal/bus.h>
#include <metal/utilities.h>

struct linux_bus *to_linux_bus(struct metal_bus *bus)
{
	return metal_container_of(bus, struct linux_bus, bus);
}

struct linux_device *to_linux_device(struct metal_device *device)
{
	return metal_container_of(device, struct linux_device, device);
}