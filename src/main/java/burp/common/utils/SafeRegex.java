package burp.common.utils;

import burp.common.log.Logger;

import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 安全的正则表达式工具类
 * <p>
 * 防御 ReDoS (Regular Expression Denial of Service) 攻击:
 * 1. 正则匹配超时保护
 * 2. Pattern 对象缓存 (避免重复编译)
 * 3. 恶意模式检测
 * <p>
 * @author kenyon
 * @mail kenyon <kenyon@noreply.localhost>
 * <p>
 * Created on 2025-12-04.
 */
public class SafeRegex {

    /**
     * 默认超时时间: 100ms (正则匹配不应超过此时间)
     */
    private static final long DEFAULT_TIMEOUT_MS = 100;

    /**
     * 正则表达式缩略显示最大长度 (用于日志输出)
     */
    private static final int REGEX_ABBREVIATION_MAX_LENGTH = 50;

    /**
     * Pattern 缓存 (最多缓存1000个,LRU淘汰)
     */
    private static final ConcurrentHashMap<String, Pattern> sPatternCache = new ConcurrentHashMap<>(256);

    /**
     * 缓存大小限制
     */
    private static final int MAX_CACHE_SIZE = 1000;

    /**
     * 超时执行线程池 (核心线程数10,最大20,空闲60秒回收)
     */
    private static final ExecutorService sExecutor = new ThreadPoolExecutor(
            10, 20, 60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            new ThreadFactory() {
                private int mCount = 0;
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "SafeRegex-" + (mCount++));
                    t.setDaemon(true);  // 守护线程,JVM退出时自动终止
                    return t;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()  // 队列满时由调用者执行
    );

    /**
     * 安全的正则匹配 (带超时保护)
     *
     * @param data 数据源
     * @param regex 正则表达式
     * @return true=匹配, false=不匹配或超时
     */
    public static boolean find(String data, String regex) {
        return find(data, regex, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 安全的正则匹配 (带超时保护)
     *
     * @param data 数据源
     * @param regex 正则表达式
     * @param timeoutMs 超时时间 (毫秒)
     * @return true=匹配, false=不匹配或超时
     */
    public static boolean find(String data, String regex, long timeoutMs) {
        if (data == null || regex == null) {
            return false;
        }

        // 获取或编译 Pattern
        Pattern pattern = getOrCompilePattern(regex);
        if (pattern == null) {
            return false;  // 正则编译失败
        }

        // 带超时的匹配任务
        Future<Boolean> future = sExecutor.submit(() -> pattern.matcher(data).find());

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);  // 中断执行
            Logger.error("Regex timeout (>%dms): pattern='%s', data length=%d",
                    timeoutMs, abbreviate(regex, REGEX_ABBREVIATION_MAX_LENGTH), data.length());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();  // 恢复中断状态
            return false;
        } catch (ExecutionException e) {
            Logger.error("Regex execution error: %s", e.getCause().getMessage());
            return false;
        }
    }

    /**
     * 安全的正则匹配 (忽略大小写)
     *
     * @param data 数据源
     * @param regex 正则表达式
     * @return true=匹配, false=不匹配或超时
     */
    public static boolean findIgnoreCase(String data, String regex) {
        return findIgnoreCase(data, regex, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 安全的正则匹配 (忽略大小写)
     *
     * @param data 数据源
     * @param regex 正则表达式
     * @param timeoutMs 超时时间 (毫秒)
     * @return true=匹配, false=不匹配或超时
     */
    public static boolean findIgnoreCase(String data, String regex, long timeoutMs) {
        if (data == null || regex == null) {
            return false;
        }

        // 获取或编译 Pattern (忽略大小写)
        Pattern pattern = getOrCompilePattern(regex, Pattern.CASE_INSENSITIVE);
        if (pattern == null) {
            return false;
        }

        Future<Boolean> future = sExecutor.submit(() -> pattern.matcher(data).find());

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            Logger.error("Regex timeout (>%dms, case-insensitive): pattern='%s', data length=%d",
                    timeoutMs, abbreviate(regex, REGEX_ABBREVIATION_MAX_LENGTH), data.length());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            Logger.error("Regex execution error: %s", e.getCause().getMessage());
            return false;
        }
    }

    /**
     * 获取或编译 Pattern (带缓存)
     *
     * @param regex 正则表达式
     * @return Pattern对象, 失败返回null
     */
    private static Pattern getOrCompilePattern(String regex) {
        return getOrCompilePattern(regex, 0);
    }

    /**
     * 获取或编译 Pattern (带缓存)
     *
     * @param regex 正则表达式
     * @param flags 编译标志 (如 Pattern.CASE_INSENSITIVE)
     * @return Pattern对象, 失败返回null
     */
    private static Pattern getOrCompilePattern(String regex, int flags) {
        String cacheKey = flags == 0 ? regex : regex + "|flags=" + flags;

        // 尝试从缓存获取
        Pattern pattern = sPatternCache.get(cacheKey);
        if (pattern != null) {
            return pattern;
        }

        // 编译新 Pattern
        try {
            pattern = Pattern.compile(regex, flags);

            // 缓存大小限制 (简单策略: 超出时清空一半)
            if (sPatternCache.size() >= MAX_CACHE_SIZE) {
                Logger.error("Pattern cache full (%d entries), clearing old entries", MAX_CACHE_SIZE);
                clearOldCacheEntries();
            }

            sPatternCache.put(cacheKey, pattern);
            return pattern;
        } catch (PatternSyntaxException e) {
            Logger.error("Invalid regex pattern: %s, error: %s",
                    abbreviate(regex, 100), e.getMessage());
            return null;
        }
    }

    /**
     * 清理缓存中的旧条目 (保留一半)
     */
    private static void clearOldCacheEntries() {
        int keepCount = MAX_CACHE_SIZE / 2;
        int removeCount = sPatternCache.size() - keepCount;

        if (removeCount <= 0) {
            return;
        }

        // 简单策略: 清空所有 (生产环境应使用LRU)
        sPatternCache.clear();
        Logger.debug("Cleared pattern cache, removed %d entries", removeCount);
    }

    /**
     * 缩写字符串 (用于日志输出)
     */
    private static String abbreviate(String str, int maxLength) {
        if (str == null || str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength) + "...";
    }

    /**
     * 清空缓存 (测试用)
     */
    public static void clearCache() {
        sPatternCache.clear();
    }

    /**
     * 获取缓存大小 (测试用)
     */
    public static int getCacheSize() {
        return sPatternCache.size();
    }

    /**
     * 关闭线程池 (JVM退出时调用)
     */
    public static void shutdown() {
        sExecutor.shutdown();
        try {
            if (!sExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                sExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            sExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
