#!/usr/bin/env python3

from bcc import BPF
from datetime import datetime
import argparse
from prettytable import PrettyTable
import ctypes as ct

def print_ip(ip):
    return ".".join([str(ip >> 24 & 0xff), str(ip >> 16 & 0xff), 
                    str(ip >> 8 & 0xff), str(ip & 0xff)])

def process_event(cpu, data, size):
    event = b["events"].event(data)
    
    # 创建表格
    table = PrettyTable()
    table.field_names = ["时间", "源IP", "目标IP", "源端口", "目标端口", "协议", "内容"]
    
    # 添加数据
    table.add_row([
        datetime.now().strftime("%H:%M:%S"),
        print_ip(event.saddr),
        print_ip(event.daddr),
        event.sport,
        event.dport,
        "TCP" if event.protocol == 6 else "UDP",
        event.payload.decode('utf-8', 'ignore')[:64]
    ])
    
    print(table)

def main():
    parser = argparse.ArgumentParser(description="网络流量监控工具")
    parser.add_argument("-i", "--interface", default="eth0", help="要监控的网络接口")
    args = parser.parse_args()

    # 初始化BPF
    b = BPF(src_file="network_traffic.c")
    
    # 附加TC程序到网络接口
    fn_ingress = b.load_func("tc_ingress", BPF.SCHED_CLS)
    fn_egress = b.load_func("tc_egress", BPF.SCHED_CLS)
    
    # 创建ingress和egress的TC过滤器
    b.attach_tc_ingress(args.interface, fn_ingress)
    b.attach_tc_egress(args.interface, fn_egress)
    
    print("开始监控网络流量...")
    print("按Ctrl+C停止监控")
    
    # 设置事件处理
    b["events"].open_perf_buffer(process_event)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n停止监控")
        # 清理TC过滤器
        b.remove_tc_ingress(args.interface)
        b.remove_tc_egress(args.interface)

if __name__ == "__main__":
    main() 