#include <stdarg.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "hyper_dmabuf_debug.h"
#include "hyper_dmabuf_drv.h"

//extern struct thread_info *current;
void tracing_mark_write(const char *str)
{
	trace_puts(str);
}
void trace_start_task(const char *fmt, ...)
{
	va_list ap;
	int len;
	char str[KATRACE_MESSAGE_LENGTH];
	len = snprintf(str, KATRACE_MESSAGE_LENGTH, "B|%d|", current->tgid);
	va_start(ap, fmt);
	len += vsnprintf(str + len, KATRACE_MESSAGE_LENGTH - len, fmt, ap);
	va_end(ap);
	tracing_mark_write(str);
}
void trace_end_task(void)
{
	tracing_mark_write("E");
}

