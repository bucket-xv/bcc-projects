#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    char payload[64];
};

BPF_PERF_OUTPUT(events);

int tc_ingress(struct __sk_buff *skb) {
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
        
    struct data_t data = {};
    data.saddr = ip->saddr;
    data.daddr = ip->daddr;
    data.protocol = ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
        data.sport = ntohs(tcp->source);
        data.dport = ntohs(tcp->dest);
        
        void *payload = (void *)tcp + sizeof(*tcp);
        if (payload + sizeof(data.payload) <= data_end) {
            bpf_skb_load_bytes(skb, (void *)tcp + sizeof(*tcp) - data, 
                             &data.payload, sizeof(data.payload));
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return TC_ACT_OK;
        data.sport = ntohs(udp->source);
        data.dport = ntohs(udp->dest);
        
        void *payload = (void *)udp + sizeof(*udp);
        if (payload + sizeof(data.payload) <= data_end) {
            bpf_skb_load_bytes(skb, (void *)udp + sizeof(*udp) - data, 
                             &data.payload, sizeof(data.payload));
        }
    }
    
    events.perf_submit_skb(skb, sizeof(data), &data);
    return TC_ACT_OK;
}

int tc_egress(struct __sk_buff *skb) {
    return tc_ingress(skb);
}