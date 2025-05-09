#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#define PAYLOAD_SIZE 8

typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

struct data_t
{
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 payload[PAYLOAD_SIZE];
};

BPF_PERF_OUTPUT(events);

int tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    struct data_t new_data = {};
    new_data.saddr = ip->saddr;
    new_data.daddr = ip->daddr;
    new_data.protocol = ip->protocol;

    u16 ip_hdr_len = ip->ihl * 4;

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(tcp->source);
        new_data.dport = ntohs(tcp->dest);

        // Extract payload
        u16 total_len = ntohs(ip->tot_len); // Convert to host byte order
        u16 tcp_hdr_len = tcp->doff * 4;
        u16 payload_offset = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
        if (skb->len > payload_offset)
        {
            if (data + payload_offset + PAYLOAD_SIZE > data_end)
                return TC_ACT_OK;
            bpf_skb_load_bytes(skb, payload_offset, new_data.payload, PAYLOAD_SIZE);
        }
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)udp + sizeof(*udp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(udp->source);
        new_data.dport = ntohs(udp->dest);

        // Extract payload
        u16 total_len = ntohs(udp->len); // Convert to host byte order
        u16 udp_hdr_len = sizeof(*udp);
        u16 payload_offset = sizeof(*eth) + ip_hdr_len + udp_hdr_len;
        if (skb->len > payload_offset)
        {
            if (data + payload_offset + PAYLOAD_SIZE > data_end)
                return TC_ACT_OK;
            bpf_skb_load_bytes(skb, payload_offset, new_data.payload, PAYLOAD_SIZE);
        }
    }

    events.perf_submit(skb, &new_data, sizeof(new_data));
    return TC_ACT_OK;
}
