package burp.onescan.ui.widget.payloadlist.rule;

import burp.common.log.Logger;
import burp.onescan.common.L;
import burp.onescan.ui.widget.payloadlist.PayloadRule;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 匹配和替换
 * <p>
 * @author kenyon
 * @mail kenyon <kenyon@noreply.localhost>
 * <p>
 * Created by vaycore on 2022-09-06.
 * Refactored by kenyon on 2025-12-04: 添加正则表达式预编译缓存和错误处理
 */
public class MatchReplace extends PayloadRule {

    /**
     * Pattern 缓存 (避免重复编译,提升性能)
     */
    private Pattern mCachedPattern = null;
    private String mCachedRegex = null;

    @Override
    public String ruleName() {
        return L.get("payload_rule.match_replace.name");
    }

    @Override
    public int paramCount() {
        return 2;
    }

    @Override
    public String paramName(int index) {
        switch (index) {
            case 0:
                return L.get("payload_rule.match_replace.param.match_regex");
            case 1:
                return L.get("payload_rule.match_replace.param.replace_with");
        }
        return "";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return L.get("payload_rule.match_replace.describe",
                handleParamValue(values[0]), handleParamValue(values[1]));
    }

    /**
     * 特殊处理 '\r'、'\n' 字符
     */
    private String handleParamValue(String paramValue) {
        if (paramValue.contains("\r")) {
            paramValue = paramValue.replaceAll("\r", "\\\\r");
        }
        if (paramValue.contains("\n")) {
            paramValue = paramValue.replaceAll("\n", "\\\\n");
        }
        return paramValue;
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        String regex = values[0];
        String replacement = values[1];

        // 正则表达式预编译缓存 (避免每次都编译)
        if (mCachedPattern == null || !regex.equals(mCachedRegex)) {
            try {
                mCachedPattern = Pattern.compile(regex);
                mCachedRegex = regex;
            } catch (PatternSyntaxException e) {
                Logger.error("Invalid regex pattern: %s, error: %s", regex, e.getMessage());
                return content;  // 正则无效,返回原内容
            }
        }

        try {
            return mCachedPattern.matcher(content).replaceAll(replacement);
        } catch (Exception e) {
            Logger.error("Regex replaceAll error: %s", e.getMessage());
            return content;  // 替换失败,返回原内容
        }
    }
}
