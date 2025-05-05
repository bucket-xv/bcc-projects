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

#define AGGR_SIZE 2

struct data_t
{
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
};

struct agg_data_t
{
    struct data_t items[AGGR_SIZE];
    u32 count;
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(agg_buffer, struct agg_data_t, 1);

static inline void submit_aggregated_data(struct __sk_buff *skb, struct agg_data_t *buf)
{
    u32 length = buf->count * sizeof(struct data_t);
    if (length > 0 && length <= AGGR_SIZE)
    {
        events.perf_submit(skb, buf->items, length);
        buf->count = 0;
    }
}

static inline void add_to_buffer(struct __sk_buff *skb, struct data_t *new_data)
{
    int idx = 0;
    struct agg_data_t *buf = agg_buffer.lookup(&idx);
    if (!buf)
        return;

    if (buf->count < AGGR_SIZE)
    {
        buf->items[buf->count] = *new_data;
        buf->count++;
    }

    if (buf->count == AGGR_SIZE)
    {
        submit_aggregated_data(skb, buf);
    }
}

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

    add_to_buffer(skb, &new_data);
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

    add_to_buffer(skb, &new_data);
    return TC_ACT_OK;
}