package burp.onescan.common;

import java.util.regex.Pattern;

/**
 * 常量
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public interface Constants {

        // 插件信息
        String PLUGIN_NAME = "OneScan";
        String PLUGIN_VERSION = "2.2.0";
        boolean DEBUG = false;

        // 插件启动显示的信息
        String BANNER = """
                        #
                        #############################################
                          %s v%s
                          Author:    0ne_1
                          Developer: vaycore
                          Developer: Rural.Dog
                          Github: https://github.com/vaycore/OneScan
                        ##############################################
                        """.formatted(PLUGIN_NAME, PLUGIN_VERSION);

        // 插件卸载显示的信息
        String UNLOAD_BANNER = """

                        ###########################################################################
                          %s uninstallation completed, thank you for your attention and use.
                        ###########################################################################
                        """.formatted(PLUGIN_NAME);

        // 匹配请求行的 URL 位置
        Pattern REGEX_REQ_LINE_URL = Pattern.compile("[A-Z]+\\s+(.*?)\\s+HTTP/", Pattern.CASE_INSENSITIVE);
}
