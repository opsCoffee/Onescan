package burp.common.utils;

import burp.common.log.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * 文件工具类
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class FileUtils {

    /**
     * File copy buffer size in bytes (8KB)
     */
    private static final int FILE_COPY_BUFFER_SIZE = 8192;

    private FileUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static boolean exists(String path) {
        return exists(new File(path));
    }

    public static boolean exists(File file) {
        return file != null && file.exists();
    }

    public static boolean isFile(String path) {
        return isFile(new File(path));
    }

    public static boolean isFile(File file) {
        return exists(file) && file.isFile();
    }

    public static boolean isDir(String path) {
        return isDir(new File(path));
    }

    public static boolean isDir(File file) {
        return exists(file) && file.isDirectory();
    }

    public static boolean mkdirs(String path) {
        return mkdirs(new File(path));
    }

    public static boolean mkdirs(File file) {
        return file != null && file.mkdirs();
    }

    public static boolean writeFile(InputStream is, String filepath) {
        return writeFile(is, new File(filepath));
    }

    public static boolean writeFile(InputStream is, File file) {
        if (is == null) {
            return false;
        }
        try (FileOutputStream fos = new FileOutputStream(file);
                InputStream inputStream = is) {
            int len;
            byte[] temp = new byte[FILE_COPY_BUFFER_SIZE];
            while ((len = inputStream.read(temp)) != -1) {
                fos.write(temp, 0, len);
            }
            fos.flush();
            return true;
        } catch (IOException e) {
            Logger.error("Failed to write file: %s - %s", file.getPath(), e.getMessage());
            return false;
        }
    }

    public static boolean writeFile(String filepath, String content) {
        return writeFile(new File(filepath), content, false);
    }

    public static boolean writeFile(String filepath, String content, boolean append) {
        return writeFile(new File(filepath), content, append);
    }

    public static boolean writeFile(File file, String content, boolean append) {
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(file, append), StandardCharsets.UTF_8)) {
            writer.write(content);
            writer.flush();
            return true;
        } catch (IOException e) {
            Logger.error("Failed to write file: %s - %s", file.getPath(), e.getMessage());
            return false;
        }
    }

    public static byte[] readFile(String filepath) {
        byte[] result = new byte[0];
        if (!isFile(filepath)) {
            return result;
        }
        try (FileInputStream fis = new FileInputStream(filepath)) {
            return IOUtils.readStream(fis);
        } catch (IOException e) {
            Logger.error("Failed to read file: %s - %s", filepath, e.getMessage());
            return result;
        }
    }

    public static String readFileToString(String filepath) {
        byte[] result = readFile(filepath);
        return new String(result, 0, result.length, StandardCharsets.UTF_8);
    }

    public static String readStreamToString(InputStream is) {
        byte[] result = IOUtils.readStream(is);
        return new String(result, 0, result.length, StandardCharsets.UTF_8);
    }

    public static ArrayList<String> readFileToList(String filepath) {
        return readFileToList(new File(filepath));
    }

    public static ArrayList<String> readFileToList(File file) {
        if (file == null || !file.exists() || !isFile(file)) {
            return null;
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            return readStreamToList(fis);
        } catch (IOException e) {
            Logger.error("Failed to read file to list: %s - %s", file.getPath(), e.getMessage());
            return null;
        }
    }

    public static ArrayList<String> readStreamToList(InputStream is) {
        if (is == null) {
            return null;
        }
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            ArrayList<String> lines = new ArrayList<>();
            String line;
            while ((line = br.readLine()) != null) {
                if (line != null) {
                    line = line.trim();
                }
                if (StringUtils.isNotEmpty(line)) {
                    lines.add(line);
                }
            }
            return lines;
        } catch (IOException e) {
            Logger.error("Failed to read stream to list: %s", e.getMessage());
            return null;
        }
    }

    public static boolean deleteFile(String filepath) {
        return deleteFile(new File(filepath));
    }

    public static boolean deleteFile(File file) {
        if (!file.exists()) {
            return false;
        }
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files == null || files.length == 0) {
                return file.delete();
            }
            for (File fileItem : files) {
                deleteFile(fileItem);
            }
        }
        return file.delete();
    }
}
