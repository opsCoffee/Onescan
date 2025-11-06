package burp.onescan;

import burp.onescan.common.Config;
import burp.onescan.manager.WordlistManager;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class ConfigCompatibilityTest {

    @Test
    public void testUpgradeFromV220Config() throws IOException {
        Path tempDir = Path.of("target", "test-work", "onescan-compat");
        Files.createDirectories(tempDir);
        // Prepare old directories to be renamed by WordlistManager
        Path wordlistDir = tempDir.resolve("wordlist");
        Files.createDirectories(wordlistDir.resolve("white-host"));
        Files.createDirectories(wordlistDir.resolve("black-host"));
        Files.createDirectories(wordlistDir.resolve("exclude-headers"));

        // Prepare old config.json with 2.2.0 version and legacy keys
        Path configPath = tempDir.resolve("config.json");
        String oldConfig = "{\n" +
                "  \"version\": \"2.2.0\",\n" +
                "  \"white-host\": \"default\",\n" +
                "  \"black-host\": \"default\",\n" +
                "  \"exclude-headers\": \"default\"\n" +
                "}";
        Files.writeString(configPath, oldConfig);

        // Initialize config pointing to tempDir; triggers upgrade flows
        Config.init(tempDir.toString());
        // Ensure wordlist path under tempDir
        burp.onescan.common.Config.put(burp.onescan.common.Config.KEY_WORDLIST_PATH,
                tempDir.resolve("wordlist").toString());
        // Re-init wordlists to perform directory rename under tempDir
        WordlistManager.init(Config.get(WordlistManager.KEY_PAYLOAD), true);

        // Assert version upgraded
        assertEquals("2.3.0", Config.getVersion());
        // Assert legacy keys migrated
        assertFalse(Config.hasKey("white-host"));
        assertFalse(Config.hasKey("black-host"));
        assertFalse(Config.hasKey("exclude-headers"));
        assertTrue(Config.hasKey(WordlistManager.KEY_HOST_ALLOWLIST));
        assertTrue(Config.hasKey(WordlistManager.KEY_HOST_BLOCKLIST));
        assertTrue(Config.hasKey(WordlistManager.KEY_REMOVE_HEADERS));
        // Assert directories renamed
        assertTrue(Files.isDirectory(wordlistDir.resolve(WordlistManager.KEY_HOST_ALLOWLIST)));
        assertTrue(Files.isDirectory(wordlistDir.resolve(WordlistManager.KEY_HOST_BLOCKLIST)));
        assertTrue(Files.isDirectory(wordlistDir.resolve(WordlistManager.KEY_REMOVE_HEADERS)));
    }
}
