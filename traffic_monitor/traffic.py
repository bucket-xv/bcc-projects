#!/usr/bin/env python3

from bcc import BPF
from datetime import datetime
import argparse
from pyroute2 import IPRoute
import time
import sys

# Compile and load BPF program
b = BPF(src_file="traffic.c", debug=0)
ipr = IPRoute()

def print_ip(ip):
    return ".".join([str(ip >> 24 & 0xff), str(ip >> 16 & 0xff), 
             str(ip >> 8 & 0xff), str(ip & 0xff)])

class EventHandler:
    def __init__(self):
        self.output_text = ""

    def process_event(self, cpu, data, size):
        event = b["events"].event(data)
        self.output_text += f"{datetime.now().strftime('%H:%M:%S')} | "
        self.output_text += f"SRC: {print_ip(event.saddr):15} | "
        self.output_text += f"DST: {print_ip(event.daddr):15} | "
        self.output_text += f"SPORT: {event.sport:5} | "
        self.output_text += f"DPORT: {event.dport:5} | "
        self.output_text += f"PROTO: {'TCP' if event.protocol == 6 else 'UDP'}\n"
    
    def print_output(self):
        print(self.output_text)
        self.output_text = ""

def main():
    parser = argparse.ArgumentParser(description="traffic monitor")
    parser.add_argument("-i", "--interface", default="enp24s0f0", help="network interface to monitor")
    args = parser.parse_args()

    try:
        ingress_fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
        egress_fn = b.load_func("tc_egress", BPF.SCHED_CLS)

        # Look up the physical interface index
        idx = ipr.link_lookup(ifname=args.interface)[0]
        
        # Clean up old rules
        try:
            ipr.tc("del", "clsact", idx)
        except:
            print("No old rules found.")
            pass

        # Create clsact qdisc for the interface
        ipr.tc("add", "clsact", idx) # tc qdisc add dev eth0 clsact

        # Add filters to the clsact qdisc
        ipr.tc("add-filter", "bpf", idx, ":1", 
            fd=ingress_fn.fd, name=ingress_fn.name, parent="ffff:fff2", direct_action=True)
        ipr.tc("add-filter", "bpf", idx, ":1", 
            fd=egress_fn.fd, name=egress_fn.name, parent="ffff:fff1", direct_action=True)
        
        print(f"BPF attached to {args.interface}. Press Ctrl+C to exit.")

        # Start monitoring traffic
        handler = EventHandler()
        b["events"].open_perf_buffer(handler.process_event)
        start_time = time.time()
        while True:
            b.perf_buffer_poll()
            # Note: This is to prevent the program from crashing
            if time.time() - start_time > 15:
                handler.print_output()
                break
    except KeyboardInterrupt:
        print("Detaching BPF program...")
    finally:
        # Cleanup: Remove tc rules
        if "idx" in locals():
            try:
                ipr.tc("del", "clsact", idx)
            except:
                pass
        print("BPF detached.")

if __name__ == "__main__":
    main() 