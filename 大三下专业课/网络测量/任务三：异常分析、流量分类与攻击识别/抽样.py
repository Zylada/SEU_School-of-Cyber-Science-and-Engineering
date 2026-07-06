import os
import shutil
from pathlib import Path
from collections import defaultdict

def sample_pcap_files(src_root, dst_root, max_per_batch=300):
    """
    保持目录结构，对每个包含 .pcap 的 batch 文件夹（叶子目录），
    最多复制 max_per_batch 个 pcap 文件到目标目录。
    """
    src_root = Path(src_root)
    dst_root = Path(dst_root)

    # 收集所有 pcap 文件
    all_pcaps = list(src_root.rglob("*.pcap"))
    print(f"找到 {len(all_pcaps)} 个 pcap 文件")

    # 按父目录（即 batch 文件夹）分组
    batch_dirs = defaultdict(list)
    for p in all_pcaps:
        batch_dirs[p.parent].append(p)

    print(f"共 {len(batch_dirs)} 个 batch 文件夹")

    total_copied = 0
    for batch_dir, files in batch_dirs.items():
        # 相对路径
        rel_dir = batch_dir.relative_to(src_root)
        dst_dir = dst_root / rel_dir
        dst_dir.mkdir(parents=True, exist_ok=True)

        # 取前 max_per_batch 个文件（按文件名排序，保证可复现）
        files_sorted = sorted(files, key=lambda x: x.name)
        for src_file in files_sorted[:max_per_batch]:
            dst_file = dst_dir / src_file.name
            shutil.copy2(src_file, dst_file)
            total_copied += 1
        print(f"复制 {min(len(files), max_per_batch)} / {len(files)} 个文件: {batch_dir}")

    print(f"\n抽样完成！共复制 {total_copied} 个 pcap 文件")
    print(f"小型数据集位于: {dst_root}")

if __name__ == "__main__":
    SOURCE_DIR = r"C:\Users\19966\Desktop\网络测量\实验三验证数据集"      # 原始完整数据集根目录
    TARGET_DIR = r"C:\Users\19966\Desktop\网络测量\sample1250"   # 输出目录
    MAX_PER_BATCH = 1250                    # 每个 batch 文件夹保留前 20 个 pcap

    sample_pcap_files(SOURCE_DIR, TARGET_DIR, MAX_PER_BATCH)