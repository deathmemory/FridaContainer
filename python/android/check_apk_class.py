import os
import re
import subprocess
import zipfile
import argparse
from pathlib import Path
import tempfile

def extract_apk(apk_path, output_dir):
    """使用 apktool 反编译 APK"""
    try:
        subprocess.run(["apktool", "d", apk_path, "-o", output_dir, "-f"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"反编译失败: {e}")
        return False
    except FileNotFoundError:
        print("未找到 apktool，请确保已安装并添加到 PATH")
        return False

def search_in_smali(smali_dir, target_class):
    """在 smali 文件中搜索类名"""
    target_path = target_class.replace(".", "/") + ".smali"
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, smali_dir)
                if rel_path.replace(os.sep, "/") == target_path:
                    return True
    return False

def search_in_dex(apk_path, target_class):
    """直接在 dex 文件中搜索类名（无需反编译）"""
    target_bytes = target_class.replace(".", "/").encode("utf-8")
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.startswith("classes") and name.endswith(".dex"):
                with z.open(name) as dex_file:
                    content = dex_file.read()
                    if target_bytes in content:
                        return True
    return False

def check_class_in_apk(apk_path, target_class, use_dex=False):
    """检查 APK 中是否包含指定类"""
    apk_path = os.path.abspath(apk_path)
    if not os.path.exists(apk_path):
        print(f"APK 文件不存在: {apk_path}")
        return False

    print(f"检查 APK: {apk_path}")
    print(f"目标类: {target_class}")

    if use_dex:
        print("使用快速模式（直接扫描 dex 文件）...")
        return search_in_dex(apk_path, target_class)
    else:
        print("使用详细模式（反编译 APK）...")
        with tempfile.TemporaryDirectory() as temp_dir:
            if extract_apk(apk_path, temp_dir):
                smali_dir = os.path.join(temp_dir, "smali")
                if os.path.exists(smali_dir):
                    return search_in_smali(smali_dir, target_class)
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="检查 APK 中是否包含指定类")
    parser.add_argument("apk_path", help="APK 文件路径")
    parser.add_argument("class_name", help="要查找的完整类名（如 com.example.Test）")
    parser.add_argument("--fast", action="store_true", help="使用快速模式（直接扫描 dex 文件）")
    args = parser.parse_args()

    if check_class_in_apk(args.apk_path, args.class_name, args.fast):
        print(f"找到类: {args.class_name}")
    else:
        print(f"未找到类: {args.class_name}")
