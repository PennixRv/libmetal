#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <metal/device.h>
#include <metal/io.h>

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    struct metal_init_params init_param = {
        .log_handler = metal_default_log_handler,
        .log_level = METAL_LOG_DEBUG,
    };
    int ret;
	ret = metal_init(&init_param);
	if (ret) {
        printf("Failed to initialize libmetal\n");
	    return ret;
    }

    struct metal_device *device;

    // Initialize libmetal device
    ret = metal_device_open("pci", "0000:09:00.0", &device);
    if (ret) {
        fprintf(stderr, "Failed to open metal device: %d\n", ret);
        return EXIT_FAILURE;
    }

    printf("VFIO PCI device initialized successfully\n");

    // metal_device_close(device);

    return EXIT_SUCCESS;
}
