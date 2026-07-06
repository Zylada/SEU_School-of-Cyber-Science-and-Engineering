import subprocess
import pandas as pd
import numpy as np
import os
import sys
from collections import defaultdict
import csv
import io

# ------------------------------------------------------------
# 1. 调用 tshark 提取每个包的字段（兼容 TCP flags 的 True/False）
# ------------------------------------------------------------
def tshark_extract_packets(pcap_path):
    fields = [
        'frame.time_relative',
        'ip.src', 'ip.dst',
        'tcp.srcport', 'udp.srcport',
        'tcp.dstport', 'udp.dstport',
        'frame.len',
        'tcp.flags.syn', 'tcp.flags.ack',
        'ip.proto',
        'icmp.type', 'icmp.code'
    ]
    tshark_path = r'E:\E_Program Data\wireshark\tshark.exe'   # 确认路径正确
    cmd = [tshark_path, '-r', pcap_path, '-T', 'fields', '-E', 'separator=,']
    for f in fields:
        cmd.extend(['-e', f])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"  tshark 错误: {result.stderr[:200]}")
            return []
        reader = csv.reader(io.StringIO(result.stdout))
        packets = []
        for parts in reader:
            if len(parts) != len(fields):
                continue
            try:
                time_val = float(parts[0]) if parts[0] else 0.0
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = int(parts[3] or parts[4] or 0)
                dst_port = int(parts[5] or parts[6] or 0)
                length = int(parts[7]) if parts[7] else 0

                # 处理 TCP flags: 可能为 'True'/'False' 或 '1'/'0'
                syn_raw = parts[8].strip().lower()
                ack_raw = parts[9].strip().lower()
                tcp_syn = 1 if syn_raw in ('true', '1') else 0
                tcp_ack = 1 if ack_raw in ('true', '1') else 0

                proto = int(parts[10]) if parts[10] else 0
                icmp_type = int(parts[11]) if parts[11] else 0
                icmp_code = int(parts[12]) if parts[12] else 0

                pkt = {
                    'time': time_val,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'len': length,
                    'tcp_syn': tcp_syn,
                    'tcp_ack': tcp_ack,
                    'proto': proto,
                    'icmp_type': icmp_type,
                    'icmp_code': icmp_code,
                }
                # 协议名称
                if pkt['proto'] == 6:
                    pkt['proto_name'] = 'tcp'
                elif pkt['proto'] == 17:
                    pkt['proto_name'] = 'udp'
                elif pkt['proto'] == 1:
                    pkt['proto_name'] = 'icmp'
                else:
                    pkt['proto_name'] = 'other'
                packets.append(pkt)
            except (ValueError, IndexError):
                # 忽略单行解析错误
                continue
        return packets
    except Exception as e:
        print(f"  执行 tshark 异常: {e}")
        return []


# ------------------------------------------------------------
# 2. 将包聚合成流，计算统计特征（包含 ICMP 的 type/code 众数）
# ------------------------------------------------------------
def packets_to_flows(packets):
    flow_dict = defaultdict(list)
    for pkt in packets:
        # 归一化五元组
        if pkt['src_ip'] < pkt['dst_ip']:
            key = (pkt['src_ip'], pkt['dst_ip'], pkt['src_port'], pkt['dst_port'], pkt['proto_name'])
        elif pkt['src_ip'] > pkt['dst_ip']:
            key = (pkt['dst_ip'], pkt['src_ip'], pkt['dst_port'], pkt['src_port'], pkt['proto_name'])
        else:
            if pkt['src_port'] < pkt['dst_port']:
                key = (pkt['src_ip'], pkt['dst_ip'], pkt['src_port'], pkt['dst_port'], pkt['proto_name'])
            else:
                key = (pkt['dst_ip'], pkt['src_ip'], pkt['dst_port'], pkt['src_port'], pkt['proto_name'])
        flow_dict[key].append(pkt)

    flows = []
    for key, pkts in flow_dict.items():
        pkts.sort(key=lambda x: x['time'])
        start = pkts[0]['time']
        end = pkts[-1]['time']
        duration = max(end - start, 0.001)
        pkt_cnt = len(pkts)
        byte_total = sum(p['len'] for p in pkts)
        avg_len = byte_total / pkt_cnt
        lens = [p['len'] for p in pkts]
        std_len = np.std(lens) if len(lens) > 1 else 0.0
        pkt_rate = pkt_cnt / duration
        byte_rate = byte_total / duration

        proto = key[4]
        dst_port = key[3]

        syn_only_ratio = 0.0
        ack_ratio = 0.0
        if proto == 'tcp':
            syn_only_cnt = sum(1 for p in pkts if p['tcp_syn'] == 1 and p['tcp_ack'] == 0)
            syn_only_ratio = syn_only_cnt / pkt_cnt if pkt_cnt else 0.0
            ack_cnt = sum(1 for p in pkts if p['tcp_ack'] == 1)
            ack_ratio = ack_cnt / pkt_cnt if pkt_cnt else 0.0

        udp_small_ratio = 0.0
        if proto == 'udp':
            small_cnt = sum(1 for p in pkts if p['len'] < 100)
            udp_small_ratio = small_cnt / pkt_cnt if pkt_cnt else 0.0

        icmp_type = 0
        icmp_code = 0
        if proto == 'icmp':
            from collections import Counter
            type_counter = Counter(p['icmp_type'] for p in pkts)
            if type_counter:
                icmp_type = type_counter.most_common(1)[0][0]
            code_counter = Counter(p['icmp_code'] for p in pkts)
            if code_counter:
                icmp_code = code_counter.most_common(1)[0][0]

        flow = {
            'flow_id': f"{key[0]}_{key[1]}_{key[2]}_{key[3]}_{key[4]}",
            'protocol': proto,
            'packet_count': pkt_cnt,
            'byte_total': byte_total,
            'duration_sec': duration,
            'avg_pkt_len': avg_len,
            'std_pkt_len': std_len,
            'pkts_per_sec': pkt_rate,
            'bytes_per_sec': byte_rate,
            'syn_only_ratio': syn_only_ratio,
            'ack_ratio': ack_ratio,
            'dst_port': dst_port,
            'udp_small_packet_ratio': udp_small_ratio,
            'icmp_type': icmp_type,
            'icmp_code': icmp_code,
        }
        flows.append(flow)
    return flows


# ------------------------------------------------------------
# 3. 处理单个 pcap 文件
# ------------------------------------------------------------
def process_pcap(pcap_path, label):
    packets = tshark_extract_packets(pcap_path)
    if not packets:
        return []
    flows = packets_to_flows(packets)
    for f in flows:
        f['label'] = label
    return flows


# ------------------------------------------------------------
# 4. 遍历整个数据集（递归查找 pcap，自动推断标签）
# ------------------------------------------------------------
def process_dataset(data_root, output_csv, label_mode='binary'):
    all_flows = []
    for split in ['train', 'test']:
        split_path = os.path.join(data_root, split)
        if not os.path.isdir(split_path):
            print(f"警告：目录不存在 {split_path}")
            continue

        for root, dirs, files in os.walk(split_path):
            for file in files:
                if not file.endswith('.pcap'):
                    continue
                pcap_full_path = os.path.join(root, file)
                rel_path = os.path.relpath(pcap_full_path, split_path)
                parts = rel_path.split(os.sep)
                # 根据路径判断标签
                if parts[0] == 'normal':
                    label = 'normal'
                elif parts[0] == 'attack':
                    if label_mode == 'binary':
                        label = 'attack'
                    else:
                        label = parts[1] if len(parts) > 1 else 'unknown'
                else:
                    print(f"跳过无法识别标签的文件: {pcap_full_path}")
                    continue

                print(f"处理: {pcap_full_path} -> 标签: {label}")
                flows = process_pcap(pcap_full_path, label)
                for fl in flows:
                    fl['split'] = split
                all_flows.extend(flows)

    if not all_flows:
        print("错误：未提取到任何流，请检查数据集路径和 pcap 文件。")
        sys.exit(1)

    df = pd.DataFrame(all_flows)
    cols = ['flow_id', 'split', 'label', 'protocol', 'packet_count', 'byte_total',
            'duration_sec', 'avg_pkt_len', 'std_pkt_len', 'pkts_per_sec', 'bytes_per_sec',
            'syn_only_ratio', 'ack_ratio', 'dst_port', 'udp_small_packet_ratio',
            'icmp_type', 'icmp_code']
    df = df[[c for c in cols if c in df.columns]]
    df.to_csv(output_csv, index=False)
    print(f"\n成功保存 {len(df)} 条流到 {output_csv}")
    print("特征列：", list(df.columns))


# ------------------------------------------------------------
# 5. 主入口
# ------------------------------------------------------------
if __name__ == '__main__':
    DATA_ROOT = r"C:\Users\19966\Desktop\网络测量\sample3"
    OUTPUT_CSV = "flow_features_3_multi.csv"
    LABEL_MODE = 'multi'
    process_dataset(DATA_ROOT, OUTPUT_CSV, LABEL_MODE)