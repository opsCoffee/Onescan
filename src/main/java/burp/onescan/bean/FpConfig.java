package burp.onescan.bean;

import burp.common.utils.FileUtils;
import burp.onescan.manager.FpManager;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.util.ArrayList;
import java.util.List;

/**
 * 指纹配置
 * <p>
 * Created by vaycore on 2025-05-19.
 */
public class FpConfig {

    /**
     * 指纹字段
     */
    private List<FpColumn> columns;

    /**
     * 指纹数据
     */
    private List<FpData> list;

    /**
     * 获取指纹字段列表
     *
     * @return 失败返回空列表
     */
    public List<FpColumn> getColumns() {
        if (columns == null) {
            columns = new ArrayList<>();
        }
        return columns;
    }

    /**
     * 获取指纹字段数量
     *
     * @return 指纹字段数量
     */
    public int getColumnsSize() {
        if (columns == null || columns.isEmpty()) {
            return 0;
        }
        return columns.size();
    }

    /**
     * 添加指纹字段
     *
     * @param column 指纹字段数据实例
     */
    public void addColumnsItem(FpColumn column) {
        if (column != null) {
            columns.add(column);
            writeToFile();
        }
    }

    /**
     * 移除指纹字段数据
     *
     * @param index 数据下标
     * @return 移除的字段数据实例
     */
    public FpColumn removeColumnsItem(int index) {
        if (index >= 0 && index < getColumnsSize()) {
            FpColumn column = columns.remove(index);
            writeToFile();
            return column;
        }
        return null;
    }

    /**
     * 更新指纹字段数据
     *
     * @param index  下标
     * @param column 指纹字段实例
     */
    public void setColumnsItem(int index, FpColumn column) {
        if (column == null || getColumnsSize() == 0) {
            return;
        }
        if (index < 0 || index >= getColumnsSize()) {
            return;
        }
        columns.set(index, column);
        writeToFile();
    }

    /**
     * 设置指纹字段列表
     *
     * @param columns 指纹字段列表
     */
    public void setColumns(ArrayList<FpColumn> columns) {
        if (columns == null) {
            this.columns = new ArrayList<>();
        } else {
            this.columns = new ArrayList<>(columns);
        }
        writeToFile();
    }

    /**
     * 获取指纹数据列表
     *
     * @return 失败返回空列表
     */
    public List<FpData> getList() {
        if (list == null) {
            list = new ArrayList<>();
        }
        return list;
    }

    /**
     * 获取指纹数据数量
     *
     * @return 指纹数量
     */
    public int getListSize() {
        if (list == null || list.isEmpty()) {
            return 0;
        }
        return list.size();
    }


    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public void addListItem(FpData data) {
        if (data != null && !data.getRules().isEmpty()) {
            list.add(data);
            writeToFile();
        }
    }

    /**
     * 移除指纹数据
     *
     * @param index 数据下标
     */
    public void removeListItem(int index) {
        if (index >= 0 && index < getListSize()) {
            list.remove(index);
            writeToFile();
        }
    }

    /**
     * 更新指纹数据
     *
     * @param index 下标
     * @param data  指纹数据实例
     */
    public void setListItem(int index, FpData data) {
        if (getListSize() == 0) {
            return;
        }
        if (index < 0 || index >= getListSize()) {
            return;
        }
        if (data != null && !data.getRules().isEmpty()) {
            list.set(index, data);
            writeToFile();
        }
    }

    /**
     * 设置指纹数据列表
     *
     * @param list 数据列表
     */
    public void setList(List<FpData> list) {
        if (list == null) {
            this.list = new ArrayList<>();
        } else {
            this.list = new ArrayList<>(list);
        }
        writeToFile();
    }

    /**
     * 写入配置到文件中
     */
    private void writeToFile() {
        // 后台保存（输出为新 YAML 格式：name + list(matchers)）
        new Thread(() -> {
            synchronized (FpConfig.class) {
                String filePath = FpManager.getPath();
                DumperOptions options = new DumperOptions();
                options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                options.setPrettyFlow(true);
                // 基础缩进 2 空格；列表项再额外缩进 2 空格，提升 content 列表的可读性
                options.setIndent(2);
                options.setIndicatorIndent(2);
                Representer representer = new Representer(options) {
                    @Override
                    protected NodeTuple representJavaBeanProperty(Object javaBean, Property property,
                                                                  Object propertyValue, Tag customTag) {
                        if (propertyValue == null) {
                            return null;
                        }
                        return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
                    }
                };
                Yaml yaml = new Yaml(representer, options);

                // 组装新格式数据结构
                java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
                String columnName = columns != null && !columns.isEmpty() ? columns.get(0).getName() : "Notes";
                String columnId = columns != null && !columns.isEmpty() ? columns.get(0).getId() : "npv";
                root.put("name", columnName);

                // 聚合输出：同名条目合并，并将相同 dataSource+field+method 的不同 content 合并为列表（逻辑与）
                java.util.List<java.util.Map<String, Object>> items = new java.util.ArrayList<>();
                if (list != null) {
                    java.util.Map<String, java.util.Map<String, Object>> agg = new java.util.LinkedHashMap<>();
                    for (FpData data : list) {
                        if (data == null || data.getRules() == null || data.getRules().isEmpty()) {
                            continue;
                        }
                        String itemName = null;
                        if (data.getParams() != null) {
                            for (FpData.Param p : data.getParams()) {
                                if (p != null && columnId.equals(p.getK())) {
                                    itemName = p.getV();
                                    break;
                                }
                            }
                        }
                        if (itemName == null) {
                            itemName = columnName;
                        }
                        java.util.Map<String, Object> holder = agg.get(itemName);
                        if (holder == null) {
                            holder = new java.util.LinkedHashMap<>();
                            holder.put("name", itemName);
                            holder.put("enabled", data.isEnabled());
                            if (data.getColor() != null) holder.put("color", data.getColor());
                            holder.put("rules", new java.util.ArrayList<FpRule>());
                            agg.put(itemName, holder);
                        } else {
                            boolean enabled = Boolean.TRUE.equals(holder.get("enabled")) || data.isEnabled();
                            holder.put("enabled", enabled);
                            if (holder.get("color") == null && data.getColor() != null) {
                                holder.put("color", data.getColor());
                            }
                        }
                        @SuppressWarnings("unchecked")
                        java.util.List<FpRule> allRules = (java.util.List<FpRule>) holder.get("rules");
                        for (java.util.ArrayList<FpRule> group : data.getRules()) {
                            if (group == null || group.isEmpty()) continue;
                            allRules.addAll(group);
                        }
                    }
                    for (java.util.Map<String, Object> holder : agg.values()) {
                        java.util.Map<String, Object> item = new java.util.LinkedHashMap<>();
                        item.put("name", holder.get("name"));
                        item.put("enabled", holder.get("enabled"));
                        if (holder.get("color") != null) item.put("color", holder.get("color"));
                        item.put("matchers-condition", "and");
                        @SuppressWarnings("unchecked")
                        java.util.List<FpRule> allRules = (java.util.List<FpRule>) holder.get("rules");
                        java.util.Map<String, java.util.Map<String, Object>> merged = new java.util.LinkedHashMap<>();
                        for (FpRule r : allRules) {
                            if (r == null) continue;
                            String ds = r.getDataSource();
                            String field = r.getField();
                            String method = r.getMethod();
                            String contentVal = r.getContent();
                            String key = String.valueOf(ds) + "\u0000" + String.valueOf(field) + "\u0000" + String.valueOf(method);
                            java.util.Map<String, Object> m = merged.get(key);
                            if (m == null) {
                                m = new java.util.LinkedHashMap<>();
                                m.put("dataSource", ds);
                                m.put("field", field);
                                m.put("method", method);
                                java.util.List<String> contents = new java.util.ArrayList<>();
                                if (contentVal != null) contents.add(contentVal);
                                m.put("content", contents);
                                merged.put(key, m);
                            } else {
                                @SuppressWarnings("unchecked")
                                java.util.List<String> contents = (java.util.List<String>) m.get("content");
                                if (contentVal != null && (contents.isEmpty() || !contents.contains(contentVal))) {
                                    contents.add(contentVal);
                                }
                            }
                        }
                        java.util.List<java.util.Map<String, Object>> matchers = new java.util.ArrayList<>();
                        for (java.util.Map<String, Object> m : merged.values()) {
                            @SuppressWarnings("unchecked")
                            java.util.List<String> contents = (java.util.List<String>) m.get("content");
                            if (contents == null || contents.isEmpty()) continue;
                            if (contents.size() == 1) {
                                m.put("content", contents.get(0));
                            } else {
                                m.put("condition", "and");
                                m.put("content", contents);
                            }
                            matchers.add(m);
                        }
                        item.put("matchers", matchers);
                        items.add(item);
                    }
                }
                root.put("list", items);

                String content = yaml.dump(root);
                FileUtils.writeFile(filePath, content);
            }
        }).start();
    }
}
