import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class TestReady {
    public static void main(String[] args) throws Exception {
        String path = "C:\\Users\\wcy\\.config\\OneScan\\wordlist\\payload\\dd.txt";
        
        // 测试1: 使用 br.ready()
        ArrayList<String> list1 = readWithReady(path);
        System.out.println("使用 br.ready() 读取行数: " + list1.size());
        
        // 测试2: 使用 readLine() != null
        ArrayList<String> list2 = readWithReadLine(path);
        System.out.println("使用 readLine() != null 读取行数: " + list2.size());
        
        // 测试3: 连续快速读取3次（模拟导入3个URL的场景）
        System.out.println("\n连续快速读取3次:");
        for (int i = 1; i <= 3; i++) {
            ArrayList<String> list = readWithReady(path);
            System.out.println("第" + i + "次读取行数: " + list.size());
        }
    }
    
    static ArrayList<String> readWithReady(String path) throws Exception {
        try (FileInputStream fis = new FileInputStream(path);
             BufferedReader br = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
            ArrayList<String> lines = new ArrayList<>();
            while (br.ready()) {
                String line = br.readLine();
                if (line != null && !line.isEmpty()) {
                    lines.add(line);
                }
            }
            return lines;
        }
    }
    
    static ArrayList<String> readWithReadLine(String path) throws Exception {
        try (FileInputStream fis = new FileInputStream(path);
             BufferedReader br = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
            ArrayList<String> lines = new ArrayList<>();
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isEmpty()) {
                    lines.add(line);
                }
            }
            return lines;
        }
    }
}
