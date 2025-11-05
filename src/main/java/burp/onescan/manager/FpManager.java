package burp.onescan.manager;

import burp.common.log.Logger;
import burp.common.utils.FileUtils;
import burp.common.utils.StringUtils;
import burp.common.utils.Utils;
import burp.onescan.bean.*;
import burp.onescan.common.FpMethodHandler;
import burp.onescan.common.OnFpColumnModifyListener;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import java.awt.*;
import java.lang.reflect.Method;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 指纹管理
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpManager {

    public static final String[] sColorNames = {
            "red",
            "orange",
            "yellow",
            "green",
            "cyan",
            "blue",
            "pink",
            "magenta",
            "gray"
    };

    public static final String[] sColorHex = {
            "#FF555D", // red
            "#FFC54D", // orange
            "#FFFF3A", // yellow
            "#00FF45", // green
            "#00FFFF", // cyan
            "#6464FF", // blue
            "#FFC5C7", // pink
            "#FF55FF", // magenta
            "#B4B4B4", // gray
    };

    private static final ConcurrentHashMap<String, List<FpData>> sFpCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, List<FpData>> sFpHistory = new ConcurrentHashMap<>();
    private static final List<OnFpColumnModifyListener> sFpColumnModifyListeners = new ArrayList<>();
    private static String sFilePath;
    private static FpConfig sConfig;

    private FpManager() {
        throw new IllegalAccessError("manager class not support create instance.");
    }

    public static void init(String path) {
        if (StringUtils.isEmpty(path) || !FileUtils.isFile(path)) {
            throw new IllegalArgumentException("fingerprint config file not found.");
        }
        sFilePath = path;
        loadConfig();
    }

    private static void loadConfig() {
        String content = FileUtils.readFileToString(sFilePath);
        if (StringUtils.isEmpty(content)) {
            throw new IllegalArgumentException(
                    "Fingerprint config file is empty: " + sFilePath
            );
        }

        // 仅支持 .yaml/.yml
        if (!(sFilePath.endsWith(".yaml") || sFilePath.endsWith(".yml"))) {
            throw new IllegalArgumentException(
                    "Unsupported fingerprint config format: " + sFilePath +
                            ". Only .yaml/.yml supported."
            );
        }

        // 解析新格式：
        // name: <ColumnName>
        // list: [ { name, enabled, color, matchers-condition, matchers: [...] }, ... ]
        Map<String, Object> root;
        try {
            LoaderOptions options = new LoaderOptions();
            options.setMaxAliasesForCollections(50);
            options.setAllowDuplicateKeys(false);
            options.setCodePointLimit(2_000_000);
            options.setNestingDepthLimit(50);
            Yaml yaml = new Yaml(options);
            Object obj = yaml.load(content);
            if (!(obj instanceof Map)) {
                throw new IllegalArgumentException("YAML root must be a mapping");
            }
            root = (Map<String, Object>) obj;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse YAML: " + e.getMessage(), e);
        }

        String columnName = valueAsString(root.get("name"));
        if (StringUtils.isEmpty(columnName)) {
            throw new IllegalArgumentException("Missing top-level 'name' for column name");
        }
        String columnId = genStableColumnId(columnName);

        Object items = root.get("list");
        if (!(items instanceof List)) {
            throw new IllegalArgumentException("Top-level 'list' must be an array");
        }

        // 构建内部运行时配置（仍使用现有 FpConfig/FpData/FpRule 以保持引擎与 UI 稳定）
        FpConfig config = new FpConfig();
        ArrayList<FpColumn> columns = new ArrayList<>();
        FpColumn fpCol = new FpColumn();
        fpCol.setId(columnId);
        fpCol.setName(columnName);
        columns.add(fpCol);
        config.setColumns(columns);

        List<FpData> dataList = new ArrayList<>();
        for (Object it : (List<?>) items) {
            if (!(it instanceof Map)) continue;
            Map<String, Object> m = (Map<String, Object>) it;
            String itemName = valueAsString(m.get("name"));
            Boolean enabled = valueAsBoolean(m.get("enabled"), Boolean.TRUE);
            String color = valueAsString(m.get("color"));
            String matchersCondition = valueAsString(m.get("matchers-condition"));
            if (StringUtils.isEmpty(matchersCondition)) matchersCondition = "and"; // 默认 and
            Object matchersObj = m.get("matchers");
            if (!(matchersObj instanceof List)) {
                throw new IllegalArgumentException("'matchers' must be an array for item: " + itemName);
            }
            List<Map<String, Object>> matchers = new ArrayList<>();
            for (Object mm : (List<?>) matchersObj) {
                if (!(mm instanceof Map)) {
                    throw new IllegalArgumentException("matcher must be a mapping for item: " + itemName);
                }
                matchers.add((Map<String, Object>) mm);
            }

            FpData data = new FpData();
            data.setEnabled(enabled);
            data.setColor(color);
            // 将条目名称写入列
            ArrayList<FpData.Param> params = new ArrayList<>();
            if (!StringUtils.isEmpty(itemName)) {
                params.add(new FpData.Param(columnId, itemName));
            }
            data.setParams(params);
            // 转换 matchers -> rules （外层 OR，组内 AND）
            ArrayList<ArrayList<FpRule>> rules = convertMatchersToRules(matchers, matchersCondition);
            if (rules == null || rules.isEmpty()) {
                throw new IllegalArgumentException("rules generated from matchers is empty for item: " + itemName);
            }
            data.setRules(rules);
            dataList.add(data);
        }
        config.setList(dataList);

        sConfig = config;

        // 校验配置并预编译
        validateConfig(sConfig);
        precompilePatterns(sConfig);
    }

    private static String valueAsString(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static Boolean valueAsBoolean(Object v, Boolean defVal) {
        if (v == null) return defVal;
        if (v instanceof Boolean) return (Boolean) v;
        String s = String.valueOf(v);
        if ("true".equalsIgnoreCase(s)) return Boolean.TRUE;
        if ("false".equalsIgnoreCase(s)) return Boolean.FALSE;
        return defVal;
    }

    private static String genStableColumnId(String name) {
        // 生成 3 位稳定 ID：基于名称计算哈希后编码为 [a-zA-Z] 范围
        int h = Math.abs(name.hashCode());
        char a = (char) ('a' + (h % 26));
        char b = (char) ('a' + ((h / 26) % 26));
        char c = (char) ('a' + ((h / (26 * 26)) % 26));
        return new String(new char[]{a, b, c});
    }

    /**
     * 将新格式 matchers 转换为内部 rules（外层 OR、组内 AND）
     */
    private static ArrayList<ArrayList<FpRule>> convertMatchersToRules(List<Map<String, Object>> matchers,
                                                                       String matchersCondition) {
        boolean topAnd = "and".equalsIgnoreCase(matchersCondition);
        if (topAnd) {
            // 从一个空组开始，逐步扩展
            ArrayList<ArrayList<FpRule>> groups = new ArrayList<>();
            groups.add(new ArrayList<>());
            for (Map<String, Object> m : matchers) {
                groups = andMerge(groups, buildGroupsFromMatcher(m));
            }
            return groups;
        } else {
            // 顶层 OR：各 matcher 独立产生 OR 组，最后合并
            ArrayList<ArrayList<FpRule>> result = new ArrayList<>();
            for (Map<String, Object> m : matchers) {
                result.addAll(buildGroupsFromMatcher(m));
            }
            return result;
        }
    }

    // 将 matcher 构造成若干 AND 组（当 content 列表且 condition=or 时产生多个组；=and 时为单一组内多条规则）
    private static ArrayList<ArrayList<FpRule>> buildGroupsFromMatcher(Map<String, Object> m) {
        String ds = valueAsString(m.get("dataSource"));
        String field = valueAsString(m.get("field"));
        String method = valueAsString(m.get("method"));
        Object contentObj = m.get("content");
        String condition = valueAsString(m.get("condition")); // and|or，仅在列表时生效

        if (StringUtils.isEmpty(ds) || StringUtils.isEmpty(field) || StringUtils.isEmpty(method)) {
            throw new IllegalArgumentException("matcher missing required fields: dataSource/field/method");
        }

        List<String> contents = new ArrayList<>();
        if (contentObj instanceof List) {
            for (Object v : (List<?>) contentObj) {
                contents.add(valueAsString(v));
            }
        } else if (contentObj != null) {
            contents.add(valueAsString(contentObj));
        } else {
            throw new IllegalArgumentException("matcher content is empty");
        }

        boolean listAnd = "and".equalsIgnoreCase(condition);

        ArrayList<ArrayList<FpRule>> groups = new ArrayList<>();
        if (contents.size() == 1 || listAnd) {
            // 单组：组内 AND 多条规则
            ArrayList<FpRule> group = new ArrayList<>();
            for (String c : contents) {
                group.add(newRule(ds, field, method, c));
            }
            groups.add(group);
        } else {
            // 列表且默认 OR：为每个内容生成一个独立组
            for (String c : contents) {
                ArrayList<FpRule> group = new ArrayList<>();
                group.add(newRule(ds, field, method, c));
                groups.add(group);
            }
        }
        return groups;
    }

    // 现有组（AND 组集合） 与 新 matcher 组集合（每元素是 AND 组）做笛卡尔乘积并合并（组内 AND）
    private static ArrayList<ArrayList<FpRule>> andMerge(ArrayList<ArrayList<FpRule>> base,
                                                         ArrayList<ArrayList<FpRule>> addon) {
        ArrayList<ArrayList<FpRule>> result = new ArrayList<>();
        for (ArrayList<FpRule> g1 : base) {
            for (ArrayList<FpRule> g2 : addon) {
                ArrayList<FpRule> merged = new ArrayList<>();
                merged.addAll(g1);
                merged.addAll(g2);
                result.add(merged);
            }
        }
        return result;
    }

    private static FpRule newRule(String ds, String field, String method, String content) {
        FpRule r = new FpRule();
        r.setDataSource(ds);
        r.setField(field);
        r.setMethod(method);
        r.setContent(content);
        return r;
    }

    /**
     * 预编译指纹规则中的正则模式
     */
    private static void precompilePatterns(FpConfig config) {
        if (config == null || config.getList() == null) {
            return;
        }
        for (FpData data : config.getList()) {
            if (data == null || data.getRules() == null) continue;
            List<ArrayList> groups = (List) data.getRules();
            for (ArrayList group : groups) {
                if (group == null) continue;
                for (int i = 0; i < group.size(); i++) {
                    Object obj = group.get(i);
                    FpRule rule;
                    if (obj instanceof FpRule) {
                        rule = (FpRule) obj;
                    } else {
                        continue;
                    }
                    compileRule(rule);
                }
            }
        }
    }

    /**
     * 预编译单个指纹数据中的正则模式（用于增量更新）
     */
    private static void precompilePatterns(FpData data) {
        if (data == null || data.getRules() == null) {
            return;
        }
        List<ArrayList> groups = (List) data.getRules();
        for (ArrayList group : groups) {
            if (group == null) continue;
            for (int i = 0; i < group.size(); i++) {
                Object obj = group.get(i);
                FpRule rule;
                if (obj instanceof FpRule) {
                    rule = (FpRule) obj;
                } else {
                    continue;
                }
                compileRule(rule);
            }
        }
    }

    private static void compileRule(FpRule rule) {
        if (rule == null) return;
        String method = rule.getMethod();
        String content = rule.getContent();
        try {
            if ("regex".equals(method)) {
                rule.setCompiled(java.util.regex.Pattern.compile(content));
            } else if ("iRegex".equals(method)) {
                rule.setCompiled(java.util.regex.Pattern.compile(content, java.util.regex.Pattern.CASE_INSENSITIVE));
            } else if ("notRegex".equals(method)) {
                rule.setCompiled(java.util.regex.Pattern.compile(content));
            } else if ("iNotRegex".equals(method)) {
                rule.setCompiled(java.util.regex.Pattern.compile(content, java.util.regex.Pattern.CASE_INSENSITIVE));
            } else {
                rule.setCompiled(null);
            }
        } catch (Exception e) {
            rule.setCompiled(null);
            Logger.error("Regex precompile error: %s", e.getMessage());
        }
    }

    

    /**
     * 校验配置文件格式
     *
     * @param config 配置实例
     * @throws IllegalArgumentException 如果配置无效
     */
    private static void validateConfig(FpConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Fingerprint config is null");
        }

        List<FpColumn> columns = config.getColumns();
        if (columns == null || columns.isEmpty()) {
            throw new IllegalArgumentException("Fingerprint config must have at least one column");
        }

        List<String> errors = new ArrayList<>();

        // 校验列：非空与唯一
        Set<String> colIds = new HashSet<>();
        Set<String> colNames = new HashSet<>();
        for (int i = 0; i < columns.size(); i++) {
            FpColumn c = columns.get(i);
            if (c == null) {
                errors.add("Column at index " + i + " is null");
                continue;
            }
            if (c.getId() == null || c.getId().trim().isEmpty()) {
                errors.add("Column id is empty at index " + i);
            } else if (!colIds.add(c.getId())) {
                errors.add("Duplicate column id: " + c.getId());
            }
            if (c.getName() == null || c.getName().trim().isEmpty()) {
                errors.add("Column name is empty for id " + c.getId());
            } else if (!colNames.add(c.getName())) {
                errors.add("Duplicate column name: " + c.getName());
            }
        }

        List<FpData> list = config.getList();
        if (list == null) {
            throw new IllegalArgumentException("Fingerprint config list cannot be null");
        }

        // 可用颜色集合（名称与十六进制）
        Set<String> colorNames = new HashSet<>(Arrays.asList(sColorNames));
        Set<String> colorHex = new HashSet<>(Arrays.asList(sColorHex));

        // 规则方法、数据源校验集合
        List<String> methods = FpRule.getMethods();
        List<String> dataSources = FpRule.getDataSources();

        // 列 id 集合
        Set<String> columnIdSet = columns.stream().filter(Objects::nonNull).map(FpColumn::getId).collect(Collectors.toSet());

        for (int i = 0; i < list.size(); i++) {
            FpData data = list.get(i);
            if (data == null) {
                errors.add("Fingerprint data at index " + i + " is null");
                continue;
            }

            // 校验颜色
            String color = data.getColor();
            if (color != null && !color.trim().isEmpty()) {
                boolean ok = colorNames.contains(color)
                        || colorHex.contains(color)
                        || color.matches("#[0-9a-fA-F]{6}");
                if (!ok) {
                    errors.add("Invalid color at data index " + i + ": " + color);
                }
            }

            // 校验参数
            List<FpData.Param> params = data.getParams();
            if (params != null) {
                Set<String> seen = new HashSet<>();
                for (int p = 0; p < params.size(); p++) {
                    FpData.Param param = params.get(p);
                    if (param == null) {
                        errors.add("Null param at data index " + i + ", param index " + p);
                        continue;
                    }
                    String k = param.getK();
                    if (k == null || k.trim().isEmpty()) {
                        errors.add("Empty param key at data index " + i + ", param index " + p);
                    } else {
                        if (!columnIdSet.contains(k)) {
                            errors.add("Unknown param key '" + k + "' at data index " + i + ", not in columns");
                        }
                        if (!seen.add(k)) {
                            errors.add("Duplicate param key '" + k + "' at data index " + i);
                        }
                    }
                }
            }

            // 校验规则
            List<ArrayList> groups = (List) data.getRules();
            if (groups == null || groups.isEmpty()) {
                errors.add("Fingerprint data at index " + i + " has no rules");
                continue;
            }
            for (int g = 0; g < groups.size(); g++) {
                ArrayList group = groups.get(g);
                if (group == null || group.isEmpty()) {
                    errors.add("Empty rule group at data index " + i + ", group index " + g);
                    continue;
                }
                for (int r = 0; r < group.size(); r++) {
                    Object obj = group.get(r);
                    String ds = null, f = null, m = null, ctn = null;
                    if (obj instanceof FpRule) {
                        FpRule rule = (FpRule) obj;
                        ds = rule.getDataSource();
                        f = rule.getField();
                        m = rule.getMethod();
                        ctn = rule.getContent();
                    } else {
                        errors.add("Unknown rule type at data index " + i + ", group " + g + ", rule " + r);
                        continue;
                    }

                    if (ds == null || ds.trim().isEmpty()) {
                        errors.add(loc(i,g,r) + "dataSource(ds) is empty");
                    } else if (!dataSources.contains(ds)) {
                        errors.add(loc(i,g,r) + "Unknown dataSource '" + ds + "'");
                    } else {
                        // 字段校验
                        List<String> fields = FpRule.getFieldsByDataSource(ds);
                        if (f == null || f.trim().isEmpty()) {
                            errors.add(loc(i,g,r) + "field(f) is empty");
                        } else if (!fields.contains(f)) {
                            errors.add(loc(i,g,r) + "Unknown field '" + f + "' for dataSource '" + ds + "'");
                        }
                    }

                    if (m == null || m.trim().isEmpty()) {
                        errors.add(loc(i,g,r) + "method(m) is empty");
                    } else if (!methods.contains(m)) {
                        errors.add(loc(i,g,r) + "Unknown method '" + m + "'");
                    }

                    if (ctn == null) {
                        errors.add(loc(i,g,r) + "content(c) is null");
                    } else if (ctn.isEmpty()) {
                        errors.add(loc(i,g,r) + "content(c) is empty");
                    }

                    // 正则方法内容合法性
                    if ("regex".equals(m) || "iRegex".equals(m) || "notRegex".equals(m) || "iNotRegex".equals(m)) {
                        try {
                            if ("iRegex".equals(m) || "iNotRegex".equals(m)) {
                                java.util.regex.Pattern.compile(ctn, java.util.regex.Pattern.CASE_INSENSITIVE);
                            } else {
                                java.util.regex.Pattern.compile(ctn);
                            }
                        } catch (Exception e) {
                            errors.add(loc(i,g,r) + "invalid regex: " + e.getMessage());
                        }
                    }
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("Fingerprint config validation failed: \n - " + String.join("\n - ", errors));
        }
    }

    private static String loc(int i, int g, int r) {
        return "data index " + i + ", group " + g + ", rule " + r + ": ";
    }

    /**
     * 检测是否初始化
     */
    private static void checkInit() {
        if (StringUtils.isEmpty(sFilePath) || sConfig == null) {
            throw new IllegalArgumentException("FpManager no init.");
        }
    }

    /**
     * 指纹识别
     *
     * @param reqBytes  HTTP 请求数据包
     * @param respBytes HTTP 响应数据包
     * @return 失败返回空列表
     */
    public static List<FpData> check(byte[] reqBytes, byte[] respBytes) {
        return check(reqBytes, respBytes, true);
    }

    /**
     * 指纹识别
     *
     * @param reqBytes  HTTP 请求数据包
     * @param respBytes HTTP 响应数据包
     * @param useCache  是否使用缓存
     * @return 失败返回空列表
     */
    public static List<FpData> check(byte[] reqBytes, byte[] respBytes, boolean useCache) {
        return check(new FpDSProvider(reqBytes, respBytes), useCache);
    }

    /**
     * 指纹识别
     *
     * @param provider 指纹数据源
     * @param useCache 是否使用缓存
     * @return 失败返回空列表
     */
    public static List<FpData> check(FpDSProvider provider, boolean useCache) {
        checkInit();
        // 提供的数据为空，不继续往下执行
        if (provider == null || provider.isEmpty()) {
            return new ArrayList<>();
        }
        String hashKey = "";
        // 判断是否启用缓存
        if (useCache) {
            hashKey = provider.getCacheKey();
            List<FpData> cacheResults = findCacheByKey(hashKey);
            if (cacheResults != null && !cacheResults.isEmpty()) {
                return cacheResults;
            }
        }
        // 没有指纹数据，不继续往下执行
        if (getCount() == 0) {
            return new ArrayList<>();
        }
        // 匹配指纹数据（仅启用的指纹）
        List<FpData> result = getList().parallelStream().filter((item) -> {
            if (item == null || !item.isEnabled()) {
                return false;
            }
            // 可能在扫描过程中存在添加/修改/删除等操作，所以不能使用 item.getRules() 获取的实例进行遍历
            ArrayList<ArrayList<FpRule>> rules = new ArrayList<>(item.getRules());
            List<ArrayList<FpRule>> checkResults = rules.parallelStream().filter((ruleItems) -> {
                if (ruleItems == null || ruleItems.isEmpty()) {
                    return false;
                }
                for (FpRule ruleItem : ruleItems) {
                    // 拿规则数据，获取数据源的数据
                    String dataSource = ruleItem.getDataSource();
                    String field = ruleItem.getField();
                    String method = ruleItem.getMethod();
                    String matchData = provider.getMatchData(dataSource, field);
                    boolean state = invokeFpMethod(method, matchData, ruleItem);
                    // 里面为 and 运算，只要有一处为 false，表示规则不匹配
                    if (!state) {
                        return false;
                    }
                }
                return true;
            }).collect(Collectors.toList());
            // 外层为 or 运算，只要结果不为空，表示规则匹配
            return !checkResults.isEmpty();
        }).collect(Collectors.toList());
        // 如果启用缓存
        if (useCache) {
            // 将指纹识别结果存放在缓存
            addResultToCache(hashKey, result);
            // 将指纹识别结果添加到历史记录
            String host = provider.getRequestHost();
            addResultToHistory(host, result);
        }
        return result;
    }

    /**
     * 获取当前指纹数据的本地文件路径
     */
    public static String getPath() {
        checkInit();
        return sFilePath;
    }

    /**
     * 获取指纹数据列表
     */
    public static List<FpData> getList() {
        checkInit();
        return new ArrayList<>(sConfig.getList());
    }

    /**
     * 获取指纹数据数量
     */
    public static int getCount() {
        checkInit();
        return sConfig.getListSize();
    }

    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public static void addItem(FpData data) {
        checkInit();
        sConfig.addListItem(data);
        // 增量预编译新加入的规则
        precompilePatterns(data);
    }

    /**
     * 移除指纹数据
     *
     * @param index 数据下标
     */
    public static void removeItem(int index) {
        checkInit();
        sConfig.removeListItem(index);
    }

    /**
     * 更新指纹数据
     *
     * @param index 下标
     * @param data  指纹数据实例
     */
    public static void setItem(int index, FpData data) {
        checkInit();
        sConfig.setListItem(index, data);
        // 增量预编译修改后的规则
        precompilePatterns(data);
    }

    /**
     * 获取指纹字段列表
     */
    public static List<FpColumn> getColumns() {
        checkInit();
        return new ArrayList<>(sConfig.getColumns());
    }

    /**
     * 根据下标，获取指纹字段 ID 值
     *
     * @return 失败返回null
     */
    public static String getColumnId(int columnIndex) {
        checkInit();
        if (columnIndex < 0 || columnIndex >= getColumnsCount()) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        FpColumn column = columns.get(columnIndex);
        return column.getId();
    }

    /**
     * 获取指纹字段名列表
     *
     * @return 失败返回空列表
     */
    public static List<String> getColumnNames() {
        checkInit();
        List<FpColumn> columns = sConfig.getColumns();
        List<String> result = new ArrayList<>(columns.size());
        for (FpColumn column : columns) {
            if (column != null) {
                result.add(column.getName());
            }
        }
        return result;
    }

    /**
     * 获取指纹字段数量
     */
    public static int getColumnsCount() {
        checkInit();
        return sConfig.getColumnsSize();
    }

    /**
     * 添加指纹字段
     *
     * @param column 指纹字段实例
     */
    public static void addColumnsItem(FpColumn column) {
        checkInit();
        sConfig.addColumnsItem(column);
        invokeFpColumnModifyListeners();
    }

    /**
     * 移除指纹字段
     *
     * @param index 数据下标
     */
    public static void removeColumnsItem(int index) {
        checkInit();
        FpColumn column = sConfig.removeColumnsItem(index);
        // 等于 null 表示删除失败
        if (column == null) {
            return;
        }
        // 同步删除指纹数据中的参数和值
        List<FpData> list = getList();
        for (FpData data : list) {
            // 遍历参数列表，过滤需要移除的参数
            List<FpData.Param> removeParams = data.getParams()
                    .stream()
                    .filter(param -> column.getId().equals(param.getK()))
                    .collect(Collectors.toList());
            // 批量移除
            data.getParams().removeAll(removeParams);
        }
        // 保存指纹数据
        sConfig.setList(list);
        invokeFpColumnModifyListeners();
    }

    /**
     * 更新指纹字段
     *
     * @param index  下标
     * @param column 指纹字段实例
     */
    public static void setColumnsItem(int index, FpColumn column) {
        checkInit();
        sConfig.setColumnsItem(index, column);
        invokeFpColumnModifyListeners();
    }

    /**
     * 根据指纹字段 ID 值，查找字段名
     *
     * @param id 字段 ID 值
     * @return 失败返回null
     */
    public static String findColumnNameById(String id) {
        checkInit();
        if (StringUtils.isEmpty(id)) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        for (FpColumn column : columns) {
            if (id.equals(column.getId())) {
                return column.getName();
            }
        }
        return null;
    }

    /**
     * 根据指纹字段名，查找字段 ID 值
     *
     * @param name 字段名
     * @return 失败返回null
     */
    public static String findColumnIdByName(String name) {
        checkInit();
        if (StringUtils.isEmpty(name)) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        for (FpColumn column : columns) {
            if (name.equals(column.getName())) {
                return column.getId();
            }
        }
        return null;
    }

    /**
     * 生成一个指纹字段实例
     *
     * @return 指纹字段实例
     */
    public static FpColumn generateFpColumn() {
        checkInit();
        String id = Utils.randomString(3);
        String name = findColumnNameById(id);
        if (name != null) {
            return generateFpColumn();
        }
        FpColumn column = new FpColumn();
        column.setId(id);
        return column;
    }

    /**
     * 调用指纹数据匹配方法
     *
     * @param methodName 方法名
     * @param data       数据源
     * @param content    要匹配的内容
     * @return true=匹配；false=不匹配
     */
    private static boolean invokeFpMethod(String methodName, String data, FpRule rule) {
        try {
            if (data == null) {
                data = "";
            }
            // 优先走预编译正则的快速路径
            if (("regex".equals(methodName) || "iRegex".equals(methodName)) && rule.getCompiled() != null) {
                return rule.getCompiled().matcher(data).find();
            }
            if (("notRegex".equals(methodName) || "iNotRegex".equals(methodName)) && rule.getCompiled() != null) {
                return !rule.getCompiled().matcher(data).find();
            }
            Method method = FpMethodHandler.class.getDeclaredMethod(methodName, String.class, String.class);
            return (Boolean) method.invoke(null, data, rule.getContent());
        } catch (Exception var4) {
            return false;
        }
    }

    /**
     * 清除指纹识别缓存
     */
    public static void clearCache() {
        if (!sFpCache.isEmpty()) {
            sFpCache.clear();
        }
    }

    /**
     * 获取指纹识别缓存数量
     */
    public static int getCacheCount() {
        return sFpCache.size();
    }

    /**
     * 根据 key 查找指纹识别缓存
     *
     * @param key 缓存 key
     * @return 失败返回null
     */
    public static List<FpData> findCacheByKey(String key) {
        checkInit();
        if (StringUtils.isEmpty(key) || !sFpCache.containsKey(key)) {
            return null;
        }
        return sFpCache.get(key);
    }

    /**
     * 添加指纹识别结果到缓存
     *
     * @param key     缓存 key
     * @param results 指纹识别结果
     */
    public static void addResultToCache(String key, List<FpData> results) {
        checkInit();
        if (StringUtils.isEmpty(key) || results == null || results.isEmpty()) {
            return;
        }
        if (!sFpCache.containsKey(key)) {
            sFpCache.put(key, new ArrayList<>(results));
        }
    }

    /**
     * 根据 Host 查找指纹识别历史记录
     *
     * @param host 请求头的 Host 数据
     * @return 失败返回null
     */
    public static List<FpData> findHistoryByHost(String host) {
        checkInit();
        if (StringUtils.isEmpty(host) || !sFpHistory.containsKey(host)) {
            return null;
        }
        return sFpHistory.get(host);
    }

    /**
     * 添加指纹识别结果到历史记录
     *
     * @param host    请求头 Host 数据
     * @param results 指纹识别结果
     */
    public static void addResultToHistory(String host, List<FpData> results) {
        checkInit();
        if (StringUtils.isEmpty(host) || results == null || results.isEmpty()) {
            return;
        }
        if (!sFpHistory.containsKey(host)) {
            sFpHistory.put(host, new ArrayList<>(results));
            return;
        }
        List<FpData> dataList = sFpHistory.get(host);
        for (FpData item : results) {
            if (dataList.contains(item)) {
                continue;
            }
            dataList.add(item);
        }
    }

    /**
     * 清除指纹识别历史记录
     */
    public static void clearHistory() {
        if (!sFpHistory.isEmpty()) {
            sFpHistory.clear();
        }
    }

    /**
     * 获取指纹识别历史记录数量
     */
    public static int getHistoryCount() {
        return sFpHistory.size();
    }

    /**
     * 通过颜色名获取颜色实例
     *
     * @param colorName 颜色名
     * @return 颜色实例
     */
    public static Color findColorByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return null;
        }
        int colorIndex = -1;
        for (int i = 0; i < sColorNames.length; i++) {
            if (sColorNames[i].equals(colorName)) {
                colorIndex = i;
                break;
            }
        }
        if (colorIndex == -1) {
            return null;
        }
        return Color.decode(sColorHex[colorIndex]);
    }

    /**
     * 通过颜色名获取颜色等级
     *
     * @param colorName 颜色名
     * @return 失败返回颜色等级最大值
     */
    public static int findColorLevelByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return sColorNames.length;
        }
        for (int i = 0; i < sColorNames.length; i++) {
            if (sColorNames[i].equals(colorName)) {
                return i;
            }
        }
        return sColorNames.length;
    }

    /**
     * 添加指纹字段修改监听器
     *
     * @param l 监听器实例
     */
    public static void addOnFpColumnModifyListener(OnFpColumnModifyListener l) {
        checkInit();
        if (sFpColumnModifyListeners.contains(l)) {
            return;
        }
        sFpColumnModifyListeners.add(l);
    }


    /**
     * 移除指纹字段修改监听器
     *
     * @param l 监听器实例
     */
    public static void removeOnFpColumnModifyListener(OnFpColumnModifyListener l) {
        checkInit();
        if (!sFpColumnModifyListeners.contains(l)) {
            return;
        }
        sFpColumnModifyListeners.remove(l);
    }

    /**
     * 清除指纹字段修改监听器
     */
    public static void clearsFpColumnModifyListeners() {
        if (sFpColumnModifyListeners.isEmpty()) {
            return;
        }
        sFpColumnModifyListeners.clear();
    }

    /**
     * 调用指纹字段修改监听器
     */
    private static void invokeFpColumnModifyListeners() {
        checkInit();
        if (sFpColumnModifyListeners.isEmpty()) {
            return;
        }
        for (OnFpColumnModifyListener l : sFpColumnModifyListeners) {
            l.onFpColumnModify();
        }
    }

    /**
     * 颜色升级算法
     *
     * @param colorLevels 颜色等级列表
     * @return 颜色名（示例：{@link FpManager#sColorNames}）；失败返回空字符串
     */
    public static String upgradeColors(Integer... colorLevels) {
        if (colorLevels == null || colorLevels.length == 0) {
            return "";
        }
        return upgradeColors(Arrays.asList(colorLevels));
    }

    /**
     * 颜色升级算法
     *
     * @param colorLevels 颜色等级列表
     * @return 颜色名（示例：{@link FpManager#sColorNames}）；失败返回空字符串
     */
    public static String upgradeColors(List<Integer> colorLevels) {
        if (colorLevels == null || colorLevels.isEmpty()) {
            return "";
        }
        // 统计每个颜色值的出现次数
        Map<Integer, Integer> frequency = new HashMap<>();
        for (int colorLevel : colorLevels) {
            int frequencyValue = frequency.getOrDefault(colorLevel, 0);
            frequency.put(colorLevel, frequencyValue + 1);
        }
        // 计算每个颜色值的最终贡献并取最小值
        int minValue = minFinalColorContribution(frequency);
        // 检测返回的颜色等级是否有效
        if (minValue >= 0 && minValue < sColorNames.length) {
            return sColorNames[minValue];
        }
        // 颜色无效返回空字符串
        return "";
    }

    /**
     * 计算每个颜色值的最终贡献并取最小值
     *
     * @param frequency 颜色出现次数的数据
     * @return 失败返回：{@link Integer#MAX_VALUE}
     */
    private static int minFinalColorContribution(Map<Integer, Integer> frequency) {
        int minIndex = Integer.MAX_VALUE;
        for (Map.Entry<Integer, Integer> entry : frequency.entrySet()) {
            int color = entry.getKey();
            int count = entry.getValue();
            // 计算可升级的次数（log2(count)）
            int steps = (int) (Math.log(count) / Math.log(2));
            int finalColor = color - steps;
            // 确保最终值在有效范围内
            int maxColorIndex = sColorNames.length - 1;
            finalColor = Math.max(0, Math.min(finalColor, maxColorIndex));
            if (finalColor < minIndex) {
                minIndex = finalColor;
            }
        }
        return minIndex;
    }
}
