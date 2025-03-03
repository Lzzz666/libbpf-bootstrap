#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP    0x0800

#define IP_P_TCP    6
#define IP_P_UDP    17

#define ETH_SIZE    sizeof(struct ethhdr)
#define IP_SIZE	    sizeof(struct iphdr)
#define UDP_SIZE    sizeof(struct udphdr)
#define TCP_SIZE    sizeof(struct tcphdr)

char __license[] SEC("license") = "Dual MIT/GPL";

struct hdr {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
};

static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end);

static __always_inline struct hdr try_parse_udp(void *data, void *data_end);

#define SERVER_COUNT 4

uint16_t server_ports[SERVER_COUNT] = { 7073, 8073, 9073, 10073 };
uint16_t redirect_port = 7072;
//uint32_t sequencer_addr = (192 << 24) | (168 << 16) | (50 << 8) | 230;
uint32_t redirect_addr = (127 << 24) | (0 << 16) | (0 << 8) | 1;
uint32_t server_ips[SERVER_COUNT] = {
    (127 << 24) | (0 << 16) | (0 << 8) | 1,
    (127 << 24) | (0 << 16) | (0 << 8) | 1,
    (127 << 24) | (0 << 16) | (0 << 8) | 1,
    (127 << 24) | (0 << 16) | (0 << 8) | 1,
};

// loopback 接口的 MAC 地址總是 00:00:00:00:00:00
unsigned char redirect_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char server_macs[SERVER_COUNT][6] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} counter_map SEC(".maps"); 

extern int bpf_dynptr_from_skb(struct sk_buff *skb, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;

extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset, void *buffer,
			      uint32_t buffer__sz) __ksym;

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

    static bool is_frag_v4(struct iphdr *iph)
{
	int offset;
	int flags;

	offset = bpf_ntohs(iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;

	return (flags & IP_MF) || offset;
}

struct ip_flags {
	uint8_t reserved;
	uint8_t df;
	uint8_t mf;
	uint16_t offset;
};

static __always_inline struct ip_flags extract_flags(uint16_t frag_off)
{
	frag_off = bpf_htons(frag_off);
	// The flags are in the first 3 bits (bits 15-13)
	// No need for htons() in the mask since we're extracting from an already network-ordered value
	uint16_t flags = (frag_off & 0xE000);

	// Right shift to get individual flags
	// Note: frag_off is already in network byte order, so we shift from the correct position
	uint8_t reserved = (flags >> 15) & 0x1; // Bit 15 (leftmost)
	uint8_t df = (flags >> 14) & 0x1; // Bit 14
	uint8_t mf = (flags >> 13) & 0x1; // Bit 13
	uint16_t offset = (flags >> 3) & 0x1FFF;
	return (struct ip_flags){ reserved, df, mf, offset };
}

struct seq_info {
    u32 sequence;
    u64 timestamp;
};

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr header = try_parse_udp(data, data_end);
	if (header.ip == NULL) {
		return TC_ACT_OK;
	}

	bool is_udp_following = false;
	bool is_udp_head = false;

	if (header.ip->ttl == 170) {
		is_udp_following = true;
	}

	if (header.udp != NULL && header.udp->dest == bpf_htons(redirect_port)) {
		is_udp_head = true;
	}

	if (!is_udp_following && !is_udp_head) {
		return TC_ACT_OK;
	}

	struct ip_flags flags = extract_flags(header.ip->frag_off);
	bool is_last_packet = false;
	if (flags.mf == 0) {
		is_last_packet = true;
	}

	const u32 counterKey = 0;
	const u32 initial_value = 1;
	
	if (is_last_packet) {
		u32 *count = bpf_map_lookup_elem(&counter_map, &counterKey);
		if (count) {
			__sync_fetch_and_add(count, 1);
		} else {
			count = &initial_value;
			bpf_map_update_elem(&counter_map, &counterKey, &initial_value, BPF_ANY);
		}

		if(count != NULL) {
			struct seq_info info;
			info.sequence = *count;
			info.timestamp = bpf_ktime_get_ns();
			bpf_printk("seq_info: %u ", info.sequence);
			bpf_printk("timestamp: %llu\n", info.timestamp);
			u32 pkt_len = (u32)(ctx->data_end - ctx->data);
			u32 pos= pkt_len - sizeof(struct seq_info);
			if (pos > 0) {
				int ret = bpf_skb_store_bytes(ctx, pos, &info, sizeof(struct seq_info), 0);
				if (ret < 0) {
					bpf_printk("Failed to store seq_info: %d\n", ret);
				}
			}
		}
	}

	int ret;
	for (int i = 0; i < SERVER_COUNT; i++) {
		if (is_udp_head) {
			uint16_t new_port = bpf_htons(server_ports[i]);
			ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_port,
				sizeof(new_port), 0);
			u16 zero16 = 0;
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, check), &zero16,
				sizeof(u16), 0);
		}

		uint32_t new_daddr = bpf_htonl(server_ips[i]);
		ret = bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_daddr,
					  sizeof(u32), 0);
		//bpf_printk("replace ip %d", ret);

		uint32_t new_saddr = bpf_htonl(redirect_addr);
		ret = bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, saddr), &new_saddr,
					  sizeof(u32), 0);

		Elf32_Half check = 0;
		bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
				    sizeof(u16), 0);
		header = try_parse_udp((void *)ctx->data, (void *)ctx->data_end);
		if (header.ip != NULL) {
			check = compute_ip_checksum(header.ip, (void *)ctx->data_end);
			ret = bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check),
						  &check, sizeof(u16), 0);
			//bpf_printk("replace check %d", ret);
		}

		ret = bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest), server_macs[i], 6,
					  0);
		ret = bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source), redirect_mac, 6,
					  0);

		ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
	}

	return TC_ACT_SHOT;
}

static __always_inline struct hdr try_parse_udp(void *data, void *data_end)
{
	if (data + ETH_SIZE > data_end)
		return (struct hdr){ NULL, NULL, NULL };

	struct ethhdr *eth = data;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return (struct hdr){ eth, NULL, NULL };

	if (data + ETH_SIZE + IP_SIZE > data_end)
		return (struct hdr){ eth, NULL, NULL };

	struct iphdr *ip = data + ETH_SIZE;

	if (ip->protocol != IP_P_UDP) {
		return (struct hdr){ eth, ip, NULL };
	}

	if (data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return (struct hdr){ eth, ip, NULL };

	struct udphdr *udp = data + ETH_SIZE + IP_SIZE;

	return (struct hdr){ eth, ip, udp };
}

static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end)
{
	__u16 *next_ip_u16 = (__u16 *)ip;
	__u16 *end = (__u16 *)data_end;
	__u32 csum = 0;

	// Ensure that `ip` is valid and does not cross data_end
	if ((void *)next_ip_u16 + sizeof(*ip) > data_end) {
		return 0; // Invalid access, return 0
	}

#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}
