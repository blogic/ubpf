#define __LITTLE_ENDIAN_BITFIELD

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"

#include "common_kern_user.h"

#define SAMPLE_SIZE 64ul
#define MAX_CPUS 128

#define min(a,b) (((a) < (b)) ? (a) : (b))

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    version:4,
		ihl:4;
#endif
	__u8    tos;
	__be16  tot_len;
	__be16  id;
	__be16  frag_off;
	__u8    ttl;
	__u8    protocol;
	__sum16 check;
	__be32  saddr;
	__be32  daddr;
}  __attribute__((packed));

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	priority:4,
		version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
		priority:4;
#endif
	__u8	flow_lbl[3];

	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;

	__be32	saddr[4];
	__be32	daddr[4];
}  __attribute__((packed));

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
}  __attribute__((packed));

struct bpf_map_def SEC("maps") uxdp_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") uxdp_pkts = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(__u32),
        .max_entries = 8,
};

struct S {
	__u16 cookie;
	__u16 pkt_len;
} __attribute__((packed)) metadata;

#define htons(x)	x

static int __always_inline parse_ipv4(void *data, __u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (((void *)iph + 1) > data_end)
		return 0;
	return iph->protocol;
}

static int __always_inline parse_ipv6(void *data, __u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (((void *)ip6h + 1) > data_end)
		return 0;
	return ip6h->nexthdr;
}

static int __always_inline handle_l2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	__u16 h_proto;
	__u64 nh_off;
	__u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP))
		ipproto = parse_ipv4(data, nh_off, data_end);
	else if (h_proto == htons(ETH_P_IPV6))
		ipproto = parse_ipv6(data, nh_off, data_end);
	else
		ipproto = 0;
	return XDP_PASS;
}

SEC("uxdp")
int uxdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_PASS;

	rec = bpf_map_lookup_elem(&uxdp_map, &key);
	if (!rec)
		return XDP_ABORTED;

	lock_xadd(&rec->rx_packets, 1);

	if (data < data_end) {
		__u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size;

		metadata.cookie = 0xdead;
		metadata.pkt_len = (__u16)(data_end - data);
		sample_size = min(metadata.pkt_len, SAMPLE_SIZE);
		flags |= (__u64)sample_size << 32;

		bpf_perf_event_output(ctx, &uxdp_pkts, flags,
				      &metadata, sizeof(metadata));
	}
	handle_l2(ctx);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
