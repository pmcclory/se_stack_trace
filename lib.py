from bcc import BPF
import ctypes as ct
import threading
import time

get_sid_prog = """
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

avc_has_perm_noaudit_prog = """
#include <uapi/linux/ptrace.h>

struct av_decision {
        u32 allowed;
        u32 auditallow;
        u32 auditdeny;
        u32 seqno;
        u32 flags;
};

BPF_HASH(decisions, u64, struct av_decision *);
BPF_HASH(requests, u64, u32);

int avc_has_perm_noaudit_probe(struct pt_regs *ctx, u32 ssid,
                         u32 tsid, u16 tclass,
                         u32 requested, u8 flags,
                         struct av_decision *avd)
{
    PID_FILTER
    SSID_FILTER
    TSID_FILTER

    // if the filters passed we wanna trace this call
    u64 tgpid = bpf_get_current_pid_tgid();
    decisions.update(&tgpid, &avd);
    requests.update(&tgpid, &requested);
    return 0;
}

int avc_has_perm_noaudit_retprobe(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct av_decision **avd_p = decisions.lookup(&key);
    struct av_decision avd;
    u32 *requested_p = requests.lookup(&key);
    u32 requested, denied;

    if (avd_p == NULL || *avd_p == NULL || requested_p == NULL) {
        return 0;
    }

    bpf_probe_read(&avd, 4, *avd_p);
    bpf_probe_read(&requested, 4, requested_p);
    denied = requested & ~(avd.allowed);
    bpf_trace_printk("denied: %d\\n", denied);
    decisions.delete(&key);
    requests.delete(&key);
    return 0;
}

"""

class SidData(ct.Structure):
    _fields_ =  [
                    ("sid", ct.c_uint),
                    ("valid", ct.c_uint),
                    ("context", ct.c_char * 128)
                ]

got_sid = False
sid = None

"""
attach a eBPF program to security_context_to_sid and
write to /sys/fs/selinux/context in order to get the current
in kernel context -> sid mapping for a given context
"""
def get_sid(context):
    # load BPF program
    b = BPF(text=get_sid_prog)
    b.attach_kprobe(event="security_context_to_sid", fn_name="security_context_to_sid_probe")
    b.attach_kretprobe(event="security_context_to_sid", fn_name="security_context_to_sid_retprobe")

    def handle_event(cpu, data, size):
        global got_sid
        global sid
        event = ct.cast(data, ct.POINTER(SidData)).contents
        if event.context == context:
            got_sid = True
            if event.valid == 1:
                sid = event.sid


    def sel_write(context):
        with open('/sys/fs/selinux/context', 'w') as sel_f:
            while not got_sid:
                sel_f.write(context)
                sel_f.flush()
                time.sleep(1)

    # kick off a thread that writes the context to
    # /sys/fs/selinux/context
    t = threading.Thread(target=sel_write, args=(context,))
    t.start()

    b["events"].open_perf_buffer(handle_event)
    while not got_sid:
        b.kprobe_poll()

    # we got here we've got the sid
    t.join()
    return sid

"""
attach a bpf program to avc_has_perm and log stacktraces
when a matching denial happens
"""
def trace(ssid, tsid, pid):
    ssid_filter, tsid_filter, pid_filter = '', '', ''

    if ssid:
        ssid_filter = 'if (ssid != %d) return -1;' % ssid
    if tsid:
        tsid_filter = 'if (tsid != %d) return -1;' % tsid
    if pid:
        pid_filter = 'if (pid != %d) return -1;' % pid

    prog_text = avc_has_perm_noaudit_prog 
    prog_text = prog_text.replace('SSID_FILTER', ssid_filter)
    prog_text = prog_text.replace('TSID_FILTER', tsid_filter)
    prog_text = prog_text.replace('PID_FILTER', pid_filter)

    b = BPF(text=prog_text)
    b.attach_kprobe(event="avc_has_perm_noaudit", fn_name="avc_has_perm_noaudit_probe")
    b.attach_kretprobe(event="avc_has_perm_noaudit", fn_name="avc_has_perm_noaudit_retprobe")

    while 1:
        b.trace_print()
