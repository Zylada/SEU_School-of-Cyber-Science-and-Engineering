import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv('flow_features_20_binary.csv')  # 你的特征文件
attack = df[df['label'] == 'attack']
normal = df[df['label'] == 'normal']

plt.figure(figsize=(12,4))
plt.subplot(1,2,1)
plt.hist(normal['avg_pkt_len'], bins=50, alpha=0.5, label='normal')
plt.hist(attack['avg_pkt_len'], bins=50, alpha=0.5, label='attack')
plt.xlabel('Avg Packet Length')
plt.legend()

plt.subplot(1,2,2)
plt.hist(normal['pkts_per_sec'], bins=50, alpha=0.5, label='normal')
plt.hist(attack['pkts_per_sec'], bins=50, alpha=0.5, label='attack')
plt.xlabel('Packets per second')
plt.legend()
plt.show()