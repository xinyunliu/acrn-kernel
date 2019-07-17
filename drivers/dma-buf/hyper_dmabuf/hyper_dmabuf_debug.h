#ifndef __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__
#define __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__

#include <linux/platform_device.h>
#include <linux/hyper_dmabuf.h>


#define KATRACE_MESSAGE_LENGTH 256

#define SURFACE_NAME_LENGTH     64

struct vm_header {
	int32_t version;
	int32_t output;
	int32_t counter;
	int32_t n_buffers;
	int32_t disp_w;
	int32_t disp_h;
};

struct vm_buffer_info {
	int32_t surf_index;
	int32_t width, height;
	int32_t format;
	int32_t pitch[3];
	int32_t offset[3];
	int32_t tile_format;
	int32_t rotation;
	int32_t status;
	int32_t counter;
	union {
		hyper_dmabuf_id_t hyper_dmabuf_id;
		unsigned long ggtt_offset;
	};
	char surface_name[SURFACE_NAME_LENGTH];
	uint64_t surface_id;
	int32_t bbox[4];
};

#define MSG_H_SIZE (sizeof(struct vm_header))
#define MSG_B_SIZE (sizeof(struct vm_buffer_info))

void trace_start_task(const char *fmt, ...);
void trace_end_task(void);

#endif /* __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__ */
