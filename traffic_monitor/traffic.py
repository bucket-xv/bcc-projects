#!/usr/bin/env python3

from bcc import BPF
from datetime import datetime
import argparse
from pyroute2 import IPRoute
import time
import sys
import ctypes

# Compile and load BPF program
b = BPF(src_file="traffic.c", debug=0)
ipr = IPRoute()

def print_ip(ip):
    return ".".join([str(ip >> 24 & 0xff), str(ip >> 16 & 0xff), 
                    str(ip >> 8 & 0xff), str(ip & 0xff)])

class DataT(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8)
    ]

class AggDataT(ctypes.Structure):
    _fields_ = [
        ("items", DataT * 1),  # AGGR_SIZE = 1
    ]

class EventHandler:
    def __init__(self):
        self.output_text = ""
        self.count = 0

    def process_event(self, cpu, data, size):
        try:
            # 将数据转换为 AggDataT 结构
            agg_data = AggDataT.from_buffer_copy(data)
            
            # 处理每个数据包
            for i in range(agg_data.count):
                event = agg_data.items[i]
                self.count += 1
                self.output_text += f"{datetime.now().strftime('%H:%M:%S')} | "
                self.output_text += f"SRC: {print_ip(event.saddr):15} | "
                self.output_text += f"DST: {print_ip(event.daddr):15} | "
                self.output_text += f"SPORT: {event.sport:5} | "
                self.output_text += f"DPORT: {event.dport:5} | "
                self.output_text += f"PROTO: {'TCP' if event.protocol == 6 else 'UDP'}\n"
                
            # 如果累积了足够的数据，就打印输出
            if self.count >= 10:
                self.print_output()
        except Exception as e:
            print(f"Error processing event: {e}")
            return
    
    def print_output(self):
        if self.output_text:
            print(self.output_text)
            self.output_text = ""

def main():
    parser = argparse.ArgumentParser(description="traffic monitor")
    parser.add_argument("-i", "--interface", default="enp24s0f0", help="network interface to monitor")
    # parser.add_argument("-o", "--output", default="output.log", help="output file")
    args = parser.parse_args()

    try:
        ingress_fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
        egress_fn = b.load_func("tc_egress", BPF.SCHED_CLS)

        # Look up the physical interface index
        idx = ipr.link_lookup(ifname=args.interface)[0]
        
        # 首先清理可能存在的旧规则
        try:
            ipr.tc("del", "ingress", idx, "ffff:")
            ipr.tc("del", "sfq", idx, "1:")
        except:
            print("No old rules found.")
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

        # Start monitoring traffic
        handler = EventHandler()
        b["events"].open_perf_buffer(handler.process_event)
        
        while True:
            b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        print("Detaching BPF program...")
    finally:
        handler.print_output()
        print(f"Total events: {handler.count}")
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