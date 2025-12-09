import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class TestReadFile {
    public static void main(String[] args) throws Exception {
        String path = "C:\\Users\\wcy\\.config\\OneScan\\wordlist\\payload\\dd.txt";
        
        // 方法1: 使用 br.ready() (当前代码的方式)
        ArrayList<String> list1 = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(path);
             BufferedReader br = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
            while (br.ready()) {
                String line = br.readLine();
                if (line != null && !line.isEmpty()) {
                    list1.add(line);
                }
            }
        }
        System.out.println("使用 br.ready() 读取行数: " + list1.size());
        
        // 方法2: 使用 readLine() != null (正确的方式)
        ArrayList<String> list2 = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(path);
             BufferedReader br = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isEmpty()) {
                    list2.add(line);
                }
            }
        }
        System.out.println("使用 readLine() != null 读取行数: " + list2.size());
        
        if (list1.size() != list2.size()) {
            System.out.println("警告: 两种方法读取的行数不同!");
            System.out.println("差异: " + (list2.size() - list1.size()) + " 行");
        }
    }
}
