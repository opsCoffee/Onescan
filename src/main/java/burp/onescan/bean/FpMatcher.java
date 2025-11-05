package burp.onescan.bean;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 指纹匹配器（nuclei 风格）
 */
public class FpMatcher implements Serializable {

    private String dataSource;
    private String field;
    private String method;
    /**
     * 支持字符串或列表（YAML 加载后会只保留到 contentList 或 contentText）
     */
    private String content; // 单值时使用
    private List<String> contents; // 列表时使用
    private String condition; // and | or（仅当 contents 非空时有效）

    // 预编译后的正则缓存
    private transient List<java.util.regex.Pattern> compiledList;

    public String getDataSource() { return dataSource; }
    public void setDataSource(String dataSource) { this.dataSource = dataSource; }

    public String getField() { return field; }
    public void setField(String field) { this.field = field; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public List<String> getContents() {
        if (contents == null) { contents = new ArrayList<>(); }
        return contents;
    }
    public void setContents(List<String> contents) { this.contents = contents; }

    public String getCondition() { return condition; }
    public void setCondition(String condition) { this.condition = condition; }

    public List<java.util.regex.Pattern> getCompiledList() { return compiledList; }
    public void setCompiledList(List<java.util.regex.Pattern> compiledList) { this.compiledList = compiledList; }
}

