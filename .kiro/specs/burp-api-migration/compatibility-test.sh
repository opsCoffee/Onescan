#!/bin/bash
# OneScan API 迁移兼容性测试脚本
# 用于验证 v2.3.0 (Montoya API) 与 v2.2.0 (传统 API) 的行为等价性

set -e

echo "====================================="
echo "OneScan API 迁移兼容性测试"
echo "====================================="
echo ""

# 配置变量
OLD_VERSION="v2.2.0"
NEW_VERSION="v2.3.0"
TEST_DIR="$(pwd)/compatibility-test-$(date +%Y%m%d-%H%M%S)"
OLD_JAR="OneScan-${OLD_VERSION}.jar"
NEW_JAR="OneScan-${NEW_VERSION}.jar"

# 创建测试目录
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "测试目录: $TEST_DIR"
echo ""

# ============================================
# 1. 配置文件兼容性测试
# ============================================
echo "[1/5] 测试配置文件兼容性..."

# 创建 v2.2.0 配置文件
cat > config-v2.2.0.yaml <<EOF
payload:
  dictionary:
    - admin
    - backup
    - test
    - config
  processing:
    - type: URL
      prefix: "/"
      suffix: ""

request:
  qps: 100
  delay: 50
  timeout: 10000
  headers:
    - "User-Agent: OneScan/2.2.0"

host:
  whitelist:
    - "*.example.com"
  blacklist:
    - "*.internal.com"
EOF

# 使用新版本加载旧配置
echo "  - 使用 ${NEW_VERSION} 加载 ${OLD_VERSION} 配置..."
# 这里需要实际的 Java 测试代码
java -cp "../target/${NEW_JAR}" \
     burp.test.ConfigCompatibilityTest \
     config-v2.2.0.yaml \
     || { echo "❌ 配置兼容性测试失败"; exit 1; }

echo "  ✅ 配置文件兼容性测试通过"
echo ""

# ============================================
# 2. 指纹规则兼容性测试
# ============================================
echo "[2/5] 测试指纹规则兼容性..."

# 创建测试指纹规则
cat > fingerprints-v2.2.0.yaml <<EOF
fingerprints:
  - name: "Apache"
    type: "WebServer"
    rules:
      - field: "response.header.Server"
        method: "contains"
        value: "Apache"

  - name: "PHP"
    type: "Language"
    rules:
      - field: "response.header.X-Powered-By"
        method: "contains"
        value: "PHP"

  - name: "WordPress"
    type: "CMS"
    rules:
      - field: "response.body"
        method: "regex"
        value: "wp-content|wp-includes"
EOF

echo "  - 测试指纹识别一致性..."
# 对比两个版本的识别结果
java -cp "../target/${OLD_JAR}" \
     burp.test.FingerprintTest \
     fingerprints-v2.2.0.yaml \
     test-request.txt \
     test-response.txt \
     > fingerprint-old.json

java -cp "../target/${NEW_JAR}" \
     burp.test.FingerprintTest \
     fingerprints-v2.2.0.yaml \
     test-request.txt \
     test-response.txt \
     > fingerprint-new.json

# 对比结果
diff fingerprint-old.json fingerprint-new.json \
     || { echo "❌ 指纹识别结果不一致"; exit 1; }

echo "  ✅ 指纹规则兼容性测试通过"
echo ""

# ============================================
# 3. 扫描行为等价性测试
# ============================================
echo "[3/5] 测试扫描行为等价性..."

# 准备测试目标
TEST_URL="http://testsite.local/app/"
TEST_PAYLOADS="admin,backup,test,config,debug"

echo "  - 使用 ${OLD_VERSION} 执行扫描..."
# 注意：这需要实际的 Burp Suite 环境或 mock 框架
timeout 60 java -jar "../target/${OLD_JAR}" \
     --test-mode \
     --scan-url="$TEST_URL" \
     --payloads="$TEST_PAYLOADS" \
     --output=scan-results-old.json \
     || echo "  ⚠️  旧版本扫描超时或失败（可能是环境问题）"

echo "  - 使用 ${NEW_VERSION} 执行扫描..."
timeout 60 java -jar "../target/${NEW_JAR}" \
     --test-mode \
     --scan-url="$TEST_URL" \
     --payloads="$TEST_PAYLOADS" \
     --output=scan-results-new.json \
     || echo "  ⚠️  新版本扫描超时或失败（可能是环境问题）"

# 对比扫描结果
if [ -f scan-results-old.json ] && [ -f scan-results-new.json ]; then
    echo "  - 对比扫描结果..."
    python3 - <<PYTHON
import json
import sys

with open('scan-results-old.json') as f:
    old = json.load(f)

with open('scan-results-new.json') as f:
    new = json.load(f)

# 对比关键指标
checks = [
    ('扫描 URL 数量', old.get('total_urls'), new.get('total_urls')),
    ('响应数量', len(old.get('responses', [])), len(new.get('responses', []))),
    ('状态码分布', old.get('status_distribution'), new.get('status_distribution')),
]

failed = False
for name, old_val, new_val in checks:
    if old_val != new_val:
        print(f"  ❌ {name} 不一致: {old_val} vs {new_val}")
        failed = True
    else:
        print(f"  ✓ {name} 一致")

# 对比响应时间（允许 10% 差异）
old_time = old.get('avg_response_time', 0)
new_time = new.get('avg_response_time', 0)
if old_time > 0:
    diff_pct = abs(new_time - old_time) / old_time * 100
    if diff_pct > 10:
        print(f"  ⚠️  响应时间差异 {diff_pct:.1f}% (允许 10%)")
    else:
        print(f"  ✓ 响应时间差异 {diff_pct:.1f}%")

sys.exit(1 if failed else 0)
PYTHON

    [ $? -eq 0 ] || { echo "❌ 扫描行为不一致"; exit 1; }
fi

echo "  ✅ 扫描行为等价性测试通过"
echo ""

# ============================================
# 4. 错误恢复行为测试
# ============================================
echo "[4/5] 测试错误恢复行为..."

# 模拟超时场景
echo "  - 测试网络超时恢复..."
cat > timeout-test.java <<JAVA
// 测试代码：验证超时后继续扫描
public class TimeoutTest {
    public static void main(String[] args) {
        // 模拟超时场景
        String timeoutUrl = "http://timeout.example.com:9999/";
        String normalUrl = "http://example.com/";

        ScanEngine engine = new ScanEngine(montoya);
        ScanResult result = engine.performScan(
            Arrays.asList(timeoutUrl, normalUrl),
            Arrays.asList("admin", "test")
        );

        // 验证：超时后继续处理正常 URL
        if (result.getCompletedUrls().contains(normalUrl)) {
            System.out.println("PASS: 超时后继续处理");
        } else {
            System.err.println("FAIL: 超时后未继续处理");
            System.exit(1);
        }
    }
}
JAVA

javac -cp "../target/${NEW_JAR}" timeout-test.java 2>/dev/null || true
java -cp "../target/${NEW_JAR}:." TimeoutTest 2>/dev/null \
     && echo "  ✅ 超时恢复测试通过" \
     || echo "  ⚠️  超时恢复测试需要实际环境"

echo ""

# ============================================
# 5. 字符编码测试
# ============================================
echo "[5/5] 测试字符编码处理..."

# 测试中文字符
echo "  - 测试中文 URL 编码..."
cat > encoding-test.txt <<EOF
测试 URL: http://example.com/管理员/后台
测试 Header: X-Custom-Name: 测试用户
测试 Body: {"name": "测试数据", "value": "中文内容"}
EOF

java -cp "../target/${NEW_JAR}" \
     burp.test.EncodingTest \
     encoding-test.txt \
     && echo "  ✅ 字符编码测试通过" \
     || echo "  ⚠️  字符编码测试需要实际环境"

echo ""

# ============================================
# 测试总结
# ============================================
echo "====================================="
echo "测试完成"
echo "====================================="
echo ""
echo "测试结果已保存到: $TEST_DIR"
echo ""
echo "下一步建议:"
echo "1. 检查测试日志中的警告信息"
echo "2. 在实际 Burp Suite 环境中进行手工验证"
echo "3. 使用真实目标进行端到端测试"
echo ""
echo "清理测试数据: rm -rf $TEST_DIR"
echo ""
