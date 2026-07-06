import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv('flow_features_20_binary.csv')
print(f"读取数据：{df.shape[0]} 条流，列：{list(df.columns)}")


# 使用实际存在的数值特征（排除 flow_id, split, label, protocol, dst_port）
feature_cols = [
    'packet_count', 'byte_total', 'duration_sec',
    'avg_pkt_len', 'std_pkt_len', 'pkts_per_sec', 'bytes_per_sec',
    'syn_only_ratio', 'ack_ratio', 'udp_small_packet_ratio',
    'icmp_type', 'icmp_code'
]
# 确保都在 DataFrame 中
feature_cols = [c for c in feature_cols if c in df.columns]
print("使用的特征列:", feature_cols)

X = df[feature_cols].fillna(0)

# 因为数据量只有 27 条，异常比例设置高一点（例如 0.2 或 0.3）更容易看到结果
model = IsolationForest(contamination=0.2, random_state=42)
df['anomaly'] = model.fit_predict(X)
df['is_attack'] = df['anomaly'] == -1

total = len(df)
anomaly_cnt = df['is_attack'].sum()
print(f"总流数: {total}")
print(f"疑似异常流数: {anomaly_cnt} (占比 {anomaly_cnt/total:.2%})")

if anomaly_cnt > 0:
    print("\n前10条可疑流:")
    suspicious = df[df['is_attack']]
    print(suspicious[['flow_id', 'protocol', 'packet_count', 'pkts_per_sec', 'syn_only_ratio', 'udp_small_packet_ratio']].head(10))
else:
    print("\n未检测到异常，改用 decision_function 取最异常的 3 条流")
    scores = model.decision_function(X)
    df['anomaly_score'] = scores
    n_outliers = min(3, len(df))
    worst_indices = scores.argsort()[:n_outliers]
    df['is_attack'] = False
    df.loc[worst_indices, 'is_attack'] = True
    anomaly_cnt = n_outliers
    print(f"强制取最异常 {anomaly_cnt} 条流")
    suspicious = df[df['is_attack']]
    print(suspicious[['flow_id', 'protocol', 'packet_count', 'pkts_per_sec', 'syn_only_ratio', 'udp_small_packet_ratio']])

# 保存可疑流
suspicious.to_csv("suspicious_flows.csv", index=False)
print("\n结果已保存到 suspicious_flows.csv")