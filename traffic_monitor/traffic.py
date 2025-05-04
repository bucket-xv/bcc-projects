#!/usr/bin/env python3

from bcc import BPF
from datetime import datetime
import argparse
from prettytable import PrettyTable
from pyroute2 import IPRoute
ipr = IPRoute()

def print_ip(ip):
    return ".".join([str(ip >> 24 & 0xff), str(ip >> 16 & 0xff), 
                    str(ip >> 8 & 0xff), str(ip & 0xff)])

def process_event(cpu, data, size):
    event = b["events"].event(data)
    
    # 创建表格
    table = PrettyTable()
    table.field_names = ["Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"]
    
    # 添加数据
    table.add_row([
        datetime.now().strftime("%H:%M:%S"),
        print_ip(event.saddr),
        print_ip(event.daddr),
        event.sport,
        event.dport,
        "TCP" if event.protocol == 6 else "UDP"
    ])
    
    # Only print the new row of the table
    print(table)

def main():
    parser = argparse.ArgumentParser(description="网络流量监控工具")
    parser.add_argument("-i", "--interface", default="enp24s0f0", help="要监控的网络接口")
    args = parser.parse_args()

    try:
        # Compile and load BPF program
        b = BPF(src_file="traffic.c", debug=0)
        ingress_fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
        egress_fn = b.load_func("tc_egress", BPF.SCHED_CLS)

        # Look up the physical interface index
        idx = ipr.link_lookup(ifname=args.interface)[0]
        
        # 首先清理可能存在的旧规则
        try:
            ipr.tc("del", "ingress", idx, "ffff:")
            ipr.tc("del", "sfq", idx, "1:")
        except:
            pass

        # Attach BPF to ingress (receive path)
        ipr.tc("add", "ingress", idx, "ffff:")
        ipr.tc("add-filter", "bpf", idx, ":1", 
            fd=ingress_fn.fd, name=ingress_fn.name, parent="ffff:", action="ok", classid=1)
        
        # Attach BPF to egress (send path)
        ipr.tc("add", "sfq", idx, "1:")
        ipr.tc("add-filter", "bpf", idx, ":1", 
            fd=egress_fn.fd, name=egress_fn.name, parent="1:", action="ok", classid=1)
        
        print(f"BPF attached to {args.interface}. Press Ctrl+C to exit.")
        b["events"].open_perf_buffer(process_event)
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Detaching BPF program...")
    finally:
        # Cleanup: Remove tc rules
        if "idx" in locals():
            try:
                ipr.tc("del", "ingress", idx, "ffff:")
                ipr.tc("del", "sfq", idx, "1:")
            except:
                pass
        print("BPF detached.")

if __name__ == "__main__":
    main() 