package burp.common.log;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.common.utils.StringUtils;

import java.io.OutputStream;
import java.io.PrintWriter;

/**
 * 日志打印模块
 * <p>
 * MIGRATE-403: 支持 Montoya API 的 Logging 接口
 * <p>
 * Created by vaycore on 2022-01-24.
 */
public class Logger {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static boolean isDebug;

    // MIGRATE-403: Montoya API 日志接口
    private static Logging montoyaLogging;

    private Logger() {
        throw new IllegalAccessError("Logger class not support create instance.");
    }

    /**
     * 初始化日志模块 (传统方式,使用 OutputStream)
     * <p>
     * 兼容旧代码
     */
    public static void init(boolean isDebug, OutputStream stdout, OutputStream stderr) {
        if (stdout == null) {
            stdout = System.out;
        }
        if (stderr == null) {
            stderr = System.err;
        }
        Logger.stdout = new PrintWriter(stdout, true);
        Logger.stderr = new PrintWriter(stderr, true);
        Logger.isDebug = isDebug;
        Logger.montoyaLogging = null;  // 清空 Montoya API
    }

    /**
     * 初始化日志模块 (Montoya API 方式)
     * <p>
     * MIGRATE-403: 使用 Montoya API 的 Logging 接口
     *
     * @param isDebug 是否开启调试模式
     * @param api     MontoyaApi 实例
     */
    public static void init(boolean isDebug, MontoyaApi api) {
        if (api == null) {
            throw new IllegalArgumentException("MontoyaApi is null");
        }
        Logger.montoyaLogging = api.logging();
        Logger.isDebug = isDebug;
        // 不再使用 stdout/stderr
        Logger.stdout = null;
        Logger.stderr = null;
    }

    public static void debug(Object log) {
        debug("%s", String.valueOf(log));
    }

    public static void debug(String format, Object... args) {
        if (!isDebug) {
            return;
        }
        if (StringUtils.isEmpty(format)) {
            return;
        }
        String message = String.format(format, args);
        if (montoyaLogging != null) {
            montoyaLogging.logToOutput(message);
        } else if (stdout != null) {
            stdout.println(message);
        }
    }

    public static void info(String format) {
        info("%s", String.valueOf(format));
    }

    public static void info(String format, Object... args) {
        if (StringUtils.isEmpty(format)) {
            return;
        }
        String message = String.format(format, args);
        if (montoyaLogging != null) {
            montoyaLogging.logToOutput(message);
        } else if (stdout != null) {
            stdout.println(message);
        }
    }

    public static void error(Object log) {
        error("%s", String.valueOf(log));
    }

    public static void error(String format, Object... args) {
        if (StringUtils.isEmpty(format)) {
            return;
        }
        String message = String.format(format, args);
        if (montoyaLogging != null) {
            montoyaLogging.logToError(message);
        } else if (stderr != null) {
            stderr.println(message);
        }
    }
}
