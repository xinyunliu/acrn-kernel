#ifndef __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__
#define __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__

#include <linux/platform_device.h>

#define KATRACE_MESSAGE_LENGTH 256
void trace_start_task(const char *fmt, ...);
void trace_end_task(void);

#endif /* __LINUX_PUBLIC_HYPER_DMABUF_DEBUG_H__ */
