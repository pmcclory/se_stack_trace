#! /usr/bin/env python

from bcc import BPF
import ctypes as ct

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
BPF_HASH(sid_ptrs, u64, u32 *, 10240);
BPF_HASH(context_ptrs, u64, const char *, 10240);

struct data_t {
    u32 sid;
    u32 valid;
    char context[128];
};

int security_context_to_sid_probe(struct pt_regs *ctx, const char *context, u32 context_len, u32 *sid)
{
    u64 tgpid = bpf_get_current_pid_tgid();
    sid_ptrs.update(&tgpid, &sid);
    context_ptrs.update(&tgpid, &context);
    return 0;
}

int security_context_to_sid_retprobe(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 key = bpf_get_current_pid_tgid();
    u32 **saved_ptr = sid_ptrs.lookup(&key);
    const char **context_ptr = context_ptrs.lookup(&key);
    char context[128];
    u32 context_len;
    struct data_t result;
    if (saved_ptr && *saved_ptr && context_ptr && *context_ptr) {
        bpf_probe_read(&result.sid, 4, *saved_ptr);
        context_len = bpf_probe_read_str(&result.context, 128, *context_ptr);

        result.valid = ret == 0;
        // write the result to user space
        if (context_len) {
            events.perf_submit(ctx, &result, sizeof(result));
        }
    }
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="security_context_to_sid", fn_name="security_context_to_sid_probe")
b.attach_kretprobe(event="security_context_to_sid", fn_name="security_context_to_sid_retprobe")


class Data(ct.Structure):
    _fields_ =[ ("sid", ct.c_uint),
                ("valid", ct.c_uint),
                ("context", ct.c_char * 128)
              ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    if event.valid:
        print("%s: %d" % (event.context, event.sid))
    else:
        print("%s: invalid context" % (event.context))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.kprobe_poll()

    except ValueError:
        continue

