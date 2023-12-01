#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


struct tcp_option_toa {
	__u8 kind;
	__u8 len;
	__u16 port;
    __u32 addr;
} __attribute__((packed));

struct user_option
{
    __u8 toa_kind;
    __u32 toa_tcp_host;
    __u16 toa_tcp_port;   
} __attribute__((packed));;


volatile struct user_option toa_options = {254,0x08080808,0x0522};


SEC("sockops")
int set_toa_tcp_bs(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op = (int) skops->op;
	switch (op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB: 
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            break;
        }
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB: {
            int option_len = sizeof(struct tcp_option_toa);
            if (skops->args[1] + option_len <= 40) {
                rv = option_len;
            }
            else {
                rv = 0;
            }
		    bpf_reserve_hdr_opt(skops, rv, 0);
            break;
        }

        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
            struct tcp_option_toa opt = {
                .kind = toa_options.toa_kind,
                .len  = 8,
                .port = bpf_htons(toa_options.toa_tcp_port),
                .addr = bpf_htonl(toa_options.toa_tcp_host),
            };

            int ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
            break;
        }
         
        default:
            rv = -1;
        }
	skops->reply = rv;
	return 1;
}

char _license[] SEC("license") = "GPL";
