#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

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
};

BPF_PERF_OUTPUT(events);

int tc_ingress(struct __sk_buff *skb)
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

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(tcp->source);
        new_data.dport = ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(udp->source);
        new_data.dport = ntohs(udp->dest);
    }

    events.perf_submit_skb(skb, sizeof(new_data), &new_data, 0);
    return TC_ACT_OK;
}

int tc_egress(struct __sk_buff *skb)
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

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(tcp->source);
        new_data.dport = ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return TC_ACT_OK;
        new_data.sport = ntohs(udp->source);
        new_data.dport = ntohs(udp->dest);
    }

    events.perf_submit_skb(skb, sizeof(new_data), &new_data, 0);
    return TC_ACT_OK;
}