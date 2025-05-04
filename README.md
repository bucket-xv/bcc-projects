# 网络流量监控工具

这是一个使用BCC（BPF Compiler Collection）实现的网络流量监控工具，可以捕获并显示所有进出的网络数据包。

## 功能特点

- 实时监控TCP和UDP流量
- 显示源IP和目标IP
- 显示源端口和目标端口
- 显示数据包内容
- 以表格形式展示结果

## 安装依赖

```bash
pip install -r requirements.txt
```

## 运行要求

- Linux系统
- Python 3.6+
- BCC工具包
- 需要root权限运行

## 使用方法

1. 确保已安装所有依赖
2. 使用root权限运行程序：

```bash
sudo python3 network_traffic_monitor.py
```

3. 可选参数：
   - `-i` 或 `--interface`: 指定要监控的网络接口（默认为eth0）

## 输出示例

程序会以表格形式显示捕获到的网络流量，包括：
- 时间戳
- 进程ID
- 源IP地址
- 目标IP地址
- 源端口
- 目标端口
- 协议类型
- 数据包内容

## 注意事项

- 需要root权限才能运行
- 某些Linux发行版可能需要安装额外的内核头文件
- 数据包内容显示限制为前64字节 