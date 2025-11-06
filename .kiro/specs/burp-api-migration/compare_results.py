#!/usr/bin/env python3
"""
OneScan 扫描结果对比工具
用于对比 v2.2.0 和 v2.3.0 的扫描结果，验证行为等价性
"""

import json
import sys
import argparse
from typing import Dict, List, Any
from collections import Counter


class ScanResultComparator:
    """扫描结果对比器"""

    def __init__(self, old_file: str, new_file: str):
        self.old_file = old_file
        self.new_file = new_file
        self.old_data = self._load_json(old_file)
        self.new_data = self._load_json(new_file)
        self.issues = []
        self.warnings = []

    def _load_json(self, filepath: str) -> Dict:
        """加载 JSON 文件"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ 加载文件失败: {filepath} - {e}", file=sys.stderr)
            sys.exit(1)

    def compare(self) -> bool:
        """执行完整对比"""
        print("=" * 60)
        print("OneScan 扫描结果对比")
        print("=" * 60)
        print(f"旧版本结果: {self.old_file}")
        print(f"新版本结果: {self.new_file}")
        print()

        # 执行各项对比
        self._compare_basic_stats()
        self._compare_urls()
        self._compare_status_codes()
        self._compare_fingerprints()
        self._compare_performance()

        # 输出结果
        self._print_summary()

        return len(self.issues) == 0

    def _compare_basic_stats(self):
        """对比基础统计"""
        print("[1/5] 对比基础统计...")

        old_total = self.old_data.get('total_urls', 0)
        new_total = self.new_data.get('total_urls', 0)

        if old_total != new_total:
            self.issues.append(
                f"扫描 URL 总数不一致: {old_total} vs {new_total}"
            )
        else:
            print(f"  ✓ 扫描 URL 总数一致: {old_total}")

        old_responses = len(self.old_data.get('responses', []))
        new_responses = len(self.new_data.get('responses', []))

        if old_responses != new_responses:
            self.issues.append(
                f"响应数量不一致: {old_responses} vs {new_responses}"
            )
        else:
            print(f"  ✓ 响应数量一致: {old_responses}")

        print()

    def _compare_urls(self):
        """对比扫描的 URL 列表"""
        print("[2/5] 对比扫描 URL 列表...")

        old_urls = set(r.get('url') for r in self.old_data.get('responses', []))
        new_urls = set(r.get('url') for r in self.new_data.get('responses', []))

        missing_in_new = old_urls - new_urls
        extra_in_new = new_urls - old_urls

        if missing_in_new:
            self.issues.append(
                f"新版本缺少 {len(missing_in_new)} 个 URL: {list(missing_in_new)[:5]}"
            )

        if extra_in_new:
            self.warnings.append(
                f"新版本多出 {len(extra_in_new)} 个 URL: {list(extra_in_new)[:5]}"
            )

        if not missing_in_new and not extra_in_new:
            print(f"  ✓ URL 列表完全一致 ({len(old_urls)} 个)")
        else:
            print(f"  ⚠️  URL 列表有差异")

        print()

    def _compare_status_codes(self):
        """对比 HTTP 状态码分布"""
        print("[3/5] 对比 HTTP 状态码分布...")

        old_codes = Counter(
            r.get('status_code') for r in self.old_data.get('responses', [])
        )
        new_codes = Counter(
            r.get('status_code') for r in self.new_data.get('responses', [])
        )

        all_codes = set(old_codes.keys()) | set(new_codes.keys())

        differences = []
        for code in sorted(all_codes):
            old_count = old_codes.get(code, 0)
            new_count = new_codes.get(code, 0)

            if old_count != new_count:
                diff_pct = abs(new_count - old_count) / max(old_count, 1) * 100
                differences.append((code, old_count, new_count, diff_pct))

        if differences:
            print("  ⚠️  状态码分布有差异:")
            for code, old_c, new_c, pct in differences[:5]:
                print(f"    {code}: {old_c} → {new_c} ({pct:+.1f}%)")

            # 如果差异超过 5%，记为问题
            major_diffs = [d for d in differences if d[3] > 5]
            if major_diffs:
                self.issues.append(
                    f"状态码分布差异超过 5%: {len(major_diffs)} 个状态码"
                )
        else:
            print("  ✓ 状态码分布完全一致")

        print()

    def _compare_fingerprints(self):
        """对比指纹识别结果"""
        print("[4/5] 对比指纹识别结果...")

        old_fps = self._extract_fingerprints(self.old_data)
        new_fps = self._extract_fingerprints(self.new_data)

        old_types = Counter(fp['type'] for fp in old_fps)
        new_types = Counter(fp['type'] for fp in new_fps)

        if old_types != new_types:
            print("  ⚠️  指纹类型分布有差异:")
            all_types = set(old_types.keys()) | set(new_types.keys())
            for fp_type in sorted(all_types):
                old_c = old_types.get(fp_type, 0)
                new_c = new_types.get(fp_type, 0)
                if old_c != new_c:
                    print(f"    {fp_type}: {old_c} → {new_c}")

            self.warnings.append("指纹识别结果有差异（可能是正常的性能优化）")
        else:
            print(f"  ✓ 指纹识别结果一致 ({len(old_fps)} 个)")

        print()

    def _extract_fingerprints(self, data: Dict) -> List[Dict]:
        """提取指纹信息"""
        fps = []
        for response in data.get('responses', []):
            if 'fingerprints' in response:
                fps.extend(response['fingerprints'])
        return fps

    def _compare_performance(self):
        """对比性能指标"""
        print("[5/5] 对比性能指标...")

        old_time = self.old_data.get('avg_response_time', 0)
        new_time = self.new_data.get('avg_response_time', 0)

        if old_time > 0 and new_time > 0:
            diff = new_time - old_time
            diff_pct = (diff / old_time) * 100

            print(f"  平均响应时间: {old_time}ms → {new_time}ms ({diff_pct:+.1f}%)")

            if diff_pct > 10:
                self.warnings.append(
                    f"响应时间增加 {diff_pct:.1f}%（可能需要性能优化）"
                )
            elif diff_pct < -10:
                print(f"  ✓ 性能提升 {abs(diff_pct):.1f}%")
            else:
                print("  ✓ 性能基本持平")
        else:
            print("  ⚠️  性能数据不完整")

        # 对比内存使用（如果有）
        old_mem = self.old_data.get('memory_usage_mb', 0)
        new_mem = self.new_data.get('memory_usage_mb', 0)

        if old_mem > 0 and new_mem > 0:
            mem_diff = new_mem - old_mem
            mem_diff_pct = (mem_diff / old_mem) * 100

            print(f"  内存使用: {old_mem}MB → {new_mem}MB ({mem_diff_pct:+.1f}%)")

            if mem_diff_pct > 20:
                self.warnings.append(
                    f"内存使用增加 {mem_diff_pct:.1f}%"
                )

        print()

    def _print_summary(self):
        """打印对比总结"""
        print("=" * 60)
        print("对比总结")
        print("=" * 60)

        if self.issues:
            print(f"\n❌ 发现 {len(self.issues)} 个问题:")
            for i, issue in enumerate(self.issues, 1):
                print(f"  {i}. {issue}")

        if self.warnings:
            print(f"\n⚠️  发现 {len(self.warnings)} 个警告:")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")

        if not self.issues and not self.warnings:
            print("\n✅ 所有对比项完全一致，迁移成功！")
        elif not self.issues:
            print("\n✅ 核心功能一致，存在少量警告（可接受）")
        else:
            print("\n❌ 发现不兼容问题，需要修复")

        print()


def main():
    parser = argparse.ArgumentParser(
        description='OneScan 扫描结果对比工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s scan-v2.2.0.json scan-v2.3.0.json
  %(prog)s old-results.json new-results.json --json

退出码:
  0: 完全一致
  1: 发现不兼容问题
  2: 仅有警告（可接受）
        """
    )

    parser.add_argument('old_file', help='旧版本扫描结果文件 (v2.2.0)')
    parser.add_argument('new_file', help='新版本扫描结果文件 (v2.3.0)')
    parser.add_argument('--json', action='store_true',
                        help='以 JSON 格式输出结果')

    args = parser.parse_args()

    # 执行对比
    comparator = ScanResultComparator(args.old_file, args.new_file)
    success = comparator.compare()

    # 返回退出码
    if success and not comparator.warnings:
        sys.exit(0)
    elif success and comparator.warnings:
        sys.exit(2)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
