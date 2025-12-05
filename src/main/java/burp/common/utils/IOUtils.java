package burp.common.utils;

import burp.common.log.Logger;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/**
 * IO工具类
 * <p>
 * Created by vaycore on 2022-01-28.
 */
public class IOUtils {

    private IOUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static void closeIO(Closeable c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (IOException e) {
            Logger.error("Failed to close IO resource: %s", e.getMessage());
        }
    }

    public static byte[] readStream(InputStream is) {
        byte[] result = new byte[0];
        if (is == null) {
            return result;
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int len;
            byte[] temp = new byte[8192];
            while ((len = is.read(temp)) != -1) {
                baos.write(temp, 0, len);
            }
            baos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            Logger.error("Failed to read stream: %s", e.getMessage());
            return result;
        }
    }
}
