import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt


def extract_flow_features(pcap_path, label):
    """
    输入：单个 pcap 文件路径 + 标签（normal 或 attack 子类名）
    输出：一条流的特征字典（DataFrame 的一行）

    注意：这里先用占位逻辑，等拿到数据后替换为 tshark 命令
    """
    # 占位：实际你会用 subprocess 调用 tshark 或 pyshark
    # 例如：
    # tshark -r file.pcap -Y "tcp" -T fields -e frame.time_relative -e ip.src -e ip.dst -e frame.len
    # 然后按五元组聚合计算特征

    # 模拟返回特征（只展示字段名，实际值需计算）
    features = {
        'packet_count': 0,
        'byte_total': 0,
        'duration_sec': 0,
        'avg_pkt_len': 0,
        'std_pkt_len': 0,
        'pkts_per_sec': 0,
        'bytes_per_sec': 0,
        'syn_only_ratio': 0,  # TCP 专用，UDP/ICMP 可为0
        'ack_ratio': 0,
        'tcp_dst_port': 0,
        'udp_dst_port': 0,
        'udp_small_packet_ratio': 0,  # < 100字节
        'icmp_type': 0,
        'icmp_code': 0,
        'protocol': 'tcp',  # 'tcp', 'udp', 'icmp'
        'label': label
    }
    return features


def save_features_to_csv(features_list, output_path):
    df = pd.DataFrame(features_list)
    df.to_csv(output_path, index=False)
    print(f"Saved {len(df)} flows to {output_path}")


def train_evaluate_classifier(train_csv, test_csv, label_col='label', task='binary'):
    """
    通用训练评估函数，支持二分类或多分类
    task = 'binary' 或 'multi'
    """
    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)

    # 特征列（去掉标签列和可能的流标识列）
    feature_cols = [c for c in train_df.columns if c != label_col]
    X_train = train_df[feature_cols]
    y_train = train_df[label_col]
    X_test = test_df[feature_cols]
    y_test = test_df[label_col]

    # 如果是二分类且标签是 normal/attack，则映射为 0/1
    if task == 'binary':
        y_train = y_train.map({'normal': 0, 'attack': 1})
        y_test = y_test.map({'normal': 0, 'attack': 1})

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 可选：画图
    disp = confusion_matrix(y_test, y_pred)
    plt.matshow(disp, cmap='Blues')
    plt.title('Confusion Matrix')
    plt.colorbar()
    plt.show()

    return model