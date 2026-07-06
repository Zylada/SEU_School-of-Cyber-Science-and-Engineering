import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

# ===== 1. 读取三个CSV文件 =====
# 请修改下面的路径为你的实际路径
path_web = r"C:\Users\19966\Desktop\网络测量\实验一相关工具\聚类\msedge_w.csv"
path_video = r"C:\Users\19966\Desktop\网络测量\实验一相关工具\聚类\video_w.csv"
path_wechat = r"C:\Users\19966\Desktop\网络测量\实验一相关工具\聚类\weixin_w.csv"

df_web = pd.read_csv(path_web)
df_video = pd.read_csv(path_video)
df_wechat = pd.read_csv(path_wechat)

# 给每个数据加上真实标签（用于后期对比）
df_web['true_label'] = 'web'
df_video['true_label'] = 'video'
df_wechat['true_label'] = 'wechat'

# 合并
data = pd.concat([df_web, df_video, df_wechat], ignore_index=True)

# ===== 2. 选择数值型特征 =====
# 排除非数值列（常见的列名）
exclude = ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'label', 'true_label']
feature_cols = [col for col in data.columns if col not in exclude and pd.api.types.is_numeric_dtype(data[col])]

# 填充缺失值（用中位数）
X = data[feature_cols].copy()
X.fillna(X.median(), inplace=True)

# ===== 3. 标准化 =====
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ===== 4. K-Means 聚类（k=3） =====
kmeans = KMeans(n_clusters=3, init='k-means++', n_init=10, random_state=42)
clusters = kmeans.fit_predict(X_scaled)
data['cluster'] = clusters

# ===== 5. PCA 降维可视化 =====
pca = PCA(n_components=2, random_state=42)
X_pca = pca.fit_transform(X_scaled)
data['pca1'] = X_pca[:, 0]
data['pca2'] = X_pca[:, 1]

plt.figure(figsize=(10,6))
scatter = plt.scatter(data['pca1'], data['pca2'], c=data['cluster'], cmap='viridis', alpha=0.6)
plt.colorbar(scatter, label='Cluster')
plt.title('K-Means Clustering of Network Flows (k=3)')
plt.xlabel('PC1')
plt.ylabel('PC2')
plt.show()

# ===== 6. 与真实标签对比 =====
print("\n=== 聚类簇 vs 真实应用类型 ===")
confusion = pd.crosstab(data['true_label'], data['cluster'])
print(confusion)

# 调整兰德指数（ARI）
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
true_encoded = le.fit_transform(data['true_label'])
ari = adjusted_rand_score(true_encoded, clusters)
print(f"\n调整兰德指数 (ARI): {ari:.3f}")

# 保存带聚类标签的结果
data.to_csv('clustered_result.csv', index=False)
print("\n带聚类标签的结果已保存为 clustered_result.csv")