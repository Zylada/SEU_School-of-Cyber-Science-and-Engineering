import subprocess
import pandas as pd
import numpy as np
import os
import sys
from collections import defaultdict
import csv
import io
import multiprocessing as mp
from functools import partial
from tqdm import tqdm

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
    tshark_path = r'E:\E_Program Data\wireshark\tshark.exe'   # 请确认你的 tshark 路径
    cmd = [tshark_path, '-n', '-r', pcap_path, '-T', 'fields', '-E', 'separator=,']
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
            # 如果字段数不足，用空字符串填充
            if len(parts) < len(fields):
                parts.extend([''] * (len(fields) - len(parts)))
            # 如果字段数过多，只取前 len(fields) 个
            parts = parts[:len(fields)]

            try:
                time_val = float(parts[0]) if parts[0] else 0.0
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = int(parts[3] or parts[4] or 0)
                dst_port = int(parts[5] or parts[6] or 0)
                length = int(parts[7]) if parts[7] else 0

                # ---------- 修复 TCP flags 解析 ----------
                syn_raw = parts[8].strip() if len(parts) > 8 else ''
                ack_raw = parts[9].strip() if len(parts) > 9 else ''
                try:
                    tcp_syn = int(syn_raw)
                except ValueError:
                    tcp_syn = 1 if syn_raw.lower() == 'true' else 0
                try:
                    tcp_ack = int(ack_raw)
                except ValueError:
                    tcp_ack = 1 if ack_raw.lower() == 'true' else 0
                # ---------------------------------------

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
                if pkt['proto'] == 6:
                    pkt['proto_name'] = 'tcp'
                elif pkt['proto'] == 17:
                    pkt['proto_name'] = 'udp'
                elif pkt['proto'] == 1:
                    pkt['proto_name'] = 'icmp'
                else:
                    pkt['proto_name'] = 'other'
                packets.append(pkt)
            except (ValueError, IndexError) as e:
                # 如果某行解析失败，跳过（不中断整个文件）
                # print(f"解析行错误: {e}, 行内容: {parts[:5]}...")
                continue
        return packets
    except Exception as e:
        print(f"  执行 tshark 异常: {e}")
        return []


# ------------------------------------------------------------
# 2. 将包聚合成流，计算统计特征
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
# 3. 处理单个 pcap 文件，返回原始流（不带标签）
# ------------------------------------------------------------
def process_pcap_raw(pcap_path):
    packets = tshark_extract_packets(pcap_path)
    if not packets:
        return []
    flows = packets_to_flows(packets)
    return flows


# ------------------------------------------------------------
# 4. 单个 pcap 的包装函数：同时生成 binary 和 multi 标签的流
# ------------------------------------------------------------
def process_one_pcap_both(pcap_path, label_binary, label_multi, split_name):
    flows = process_pcap_raw(pcap_path)
    flows_binary = []
    flows_multi = []
    for flow in flows:
        # Binary 副本
        f_binary = flow.copy()
        f_binary['label'] = label_binary
        f_binary['split'] = split_name
        flows_binary.append(f_binary)

        # Multi 副本
        f_multi = flow.copy()
        f_multi['label'] = label_multi
        f_multi['split'] = split_name
        flows_multi.append(f_multi)
    return flows_binary, flows_multi


# ------------------------------------------------------------
# 5. 并行遍历 validation 目录，同时生成两个 CSV
# ------------------------------------------------------------
def process_validation_both(validation_root, output_binary, output_multi, num_workers=None):
    if num_workers is None:
        num_workers = mp.cpu_count()

    if not os.path.isdir(validation_root):
        print(f"错误：目录不存在 {validation_root}")
        sys.exit(1)

    # ---- 第一步：收集所有任务，同时确定每个 pcap 的两种标签 ----
    tasks = []  # 每个元素为 (pcap_path, label_binary, label_multi)
    for root, dirs, files in os.walk(validation_root):
        for file in files:
            if not file.endswith('.pcap'):
                continue
            pcap_full_path = os.path.join(root, file)
            rel_path = os.path.relpath(pcap_full_path, validation_root)
            parts = rel_path.split(os.sep)

            # 根据路径判断标签
            if parts[0] == 'normal':
                label_binary = 'normal'
                label_multi = 'normal'
            elif parts[0] == 'attack':
                label_binary = 'attack'
                # 攻击类型名通常在 parts[1]
                if len(parts) > 1:
                    label_multi = parts[1]
                else:
                    label_multi = 'unknown'
            else:
                print(f"跳过无法识别标签的文件: {pcap_full_path}")
                continue

            tasks.append((pcap_full_path, label_binary, label_multi))

    print(f"共收集 {len(tasks)} 个 pcap 文件，将使用 {num_workers} 个进程并行处理...")

    if not tasks:
        print("错误：未找到任何 pcap 文件")
        sys.exit(1)

    # ---- 第二步：多进程执行 ----
    split_name = 'validation'
    worker_func = partial(process_one_pcap_both, split_name=split_name)

    all_binary = []
    all_multi = []

    with mp.Pool(processes=num_workers) as pool:
        # 使用 tqdm 显示进度
        results = list(tqdm(pool.starmap(worker_func, tasks), total=len(tasks), desc="处理 pcap"))

    # ---- 第三步：合并结果 ----
    for flows_b, flows_m in results:
        all_binary.extend(flows_b)
        all_multi.extend(flows_m)

    # ---- 第四步：保存 CSV ----
    if not all_binary:
        print("错误：未提取到任何 binary 流")
        sys.exit(1)

    df_binary = pd.DataFrame(all_binary)
    cols = ['flow_id', 'split', 'label', 'protocol', 'packet_count', 'byte_total',
            'duration_sec', 'avg_pkt_len', 'std_pkt_len', 'pkts_per_sec', 'bytes_per_sec',
            'syn_only_ratio', 'ack_ratio', 'dst_port', 'udp_small_packet_ratio',
            'icmp_type', 'icmp_code']
    df_binary = df_binary[[c for c in cols if c in df_binary.columns]]
    df_binary.to_csv(output_binary, index=False)
    print(f"\n成功保存 {len(df_binary)} 条 binary 流到 {output_binary}")

    df_multi = pd.DataFrame(all_multi)
    df_multi = df_multi[[c for c in cols if c in df_multi.columns]]
    df_multi.to_csv(output_multi, index=False)
    print(f"成功保存 {len(df_multi)} 条 multi 流到 {output_multi}")
    print("特征列：", list(df_binary.columns))


# ------------------------------------------------------------
# 6. 主入口
# ------------------------------------------------------------
if __name__ == '__main__':
    # ================= 请修改以下路径 =================
    VALIDATION_ROOT = r"C:\Users\19966\Desktop\网络测量\sample1250\validation"   # validation 数据集根目录
    OUTPUT_BINARY = "validation_binary.csv"           # 二分类版本输出
    OUTPUT_MULTI  = "validation_multi.csv"            # 多分类版本输出
    NUM_WORKERS = 8                                   # 并行进程数，可根据 CPU 核心数调整
    # =================================================

    process_validation_both(VALIDATION_ROOT, OUTPUT_BINARY, OUTPUT_MULTI, num_workers=NUM_WORKERS)