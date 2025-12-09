import burp.onescan.manager.FpManager;
import burp.onescan.bean.FpData;
import burp.common.utils.FileUtils;
import java.io.File;

/**
 * 简单测试指纹配置保存功能
 */
public class TestFpSave {
    public static void main(String[] args) {
        try {
            // 创建测试配置文件
            String testConfigPath = "test_fingerprint.yaml";
            String testContent = """
                name: "测试指纹"
                list:
                  - name: "测试规则1"
                    enabled: true
                    color: "red"
                    matchers-condition: "and"
                    matchers:
                      - dataSource: "response"
                        field: "body"
                        method: "contains"
                        content: "test"
                """;
            
            // 写入测试配置
            FileUtils.writeFile(testConfigPath, testContent);
            
            // 初始化FpManager
            FpManager.init(testConfigPath);
            
            // 获取第一个指纹数据并修改
            if (FpManager.getCount() > 0) {
                FpData data = FpManager.getList().get(0);
                data.setEnabled(false); // 修改启用状态
                
                // 更新指纹数据（这应该触发保存）
                FpManager.setItem(0, data);
                
                System.out.println("指纹配置保存测试完成");
                System.out.println("配置文件路径: " + testConfigPath);
                
                // 读取保存后的文件内容
                String savedContent = FileUtils.readFileToString(testConfigPath);
                System.out.println("保存后的内容:");
                System.out.println(savedContent);
            }
            
            // 清理测试文件
            new File(testConfigPath).delete();
            
        } catch (Exception e) {
            System.err.println("测试失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}