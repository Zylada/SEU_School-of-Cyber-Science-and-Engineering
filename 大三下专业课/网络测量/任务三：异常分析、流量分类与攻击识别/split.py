import pandas as pd

df = pd.read_csv("flow_features_20_multi.csv")
train_df = df[df['split'] == 'train']
test_df  = df[df['split'] == 'test']

# 去掉 split 列（因为文件名已经区分）
train_df = train_df.drop(columns=['split'])
test_df  = test_df.drop(columns=['split'])

train_df.to_csv("multi_train_features.csv", index=False)
test_df.to_csv("multi_test_features.csv", index=False)