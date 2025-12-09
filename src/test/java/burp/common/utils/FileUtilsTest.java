/**
 * @author kenyon
 * @mail kenyon <kenyon@noreply.localhost>
 */
package burp.common.utils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import static org.junit.Assert.*;

public class FileUtilsTest {

    private File mTempFile;

    @Before
    public void setUp() {
        // Create a temporary test file
        try {
            mTempFile = File.createTempFile("test_fileutils_", ".txt");
            mTempFile.deleteOnExit();
        } catch (IOException e) {
            fail("Failed to create temp file: " + e.getMessage());
        }
    }

    @After
    public void tearDown() {
        if (mTempFile != null && mTempFile.exists()) {
            mTempFile.delete();
        }
    }

    /**
     * Test reading a small file (< 8KB buffer)
     * This test verifies the fix works for files smaller than BufferedReader's default buffer size
     */
    @Test
    public void testReadStreamToList_SmallFile() {
        // Arrange: Create a small content (< 8KB)
        StringBuilder content = new StringBuilder();
        for (int i = 1; i <= 92; i++) {
            content.append("line").append(i).append("\n");
        }

        ByteArrayInputStream is = new ByteArrayInputStream(content.toString().getBytes(StandardCharsets.UTF_8));

        // Act
        ArrayList<String> result = FileUtils.readStreamToList(is);

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Should read all 92 lines", 92, result.size());
        assertEquals("First line should be correct", "line1", result.get(0));
        assertEquals("Last line should be correct", "line92", result.get(91));
    }

    /**
     * Test reading a large file (> 8KB buffer)
     * This is the CRITICAL test that reproduces the original bug:
     * - BufferedReader default buffer: 8192 bytes (8KB)
     * - dd.txt size: 9940 bytes (> 8KB)
     *
     * The old code using br.ready() would fail to read beyond the buffer boundary.
     */
    @Test
    public void testReadStreamToList_LargeFile() {
        // Arrange: Create a large content (> 8KB, ~10KB like dd.txt)
        StringBuilder content = new StringBuilder();
        // Each line is approximately 28 bytes, so 348 lines ≈ 9744 bytes
        for (int i = 1; i <= 348; i++) {
            content.append("payload_line_").append(i).append("\n");
        }

        ByteArrayInputStream is = new ByteArrayInputStream(content.toString().getBytes(StandardCharsets.UTF_8));

        // Act
        ArrayList<String> result = FileUtils.readStreamToList(is);

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Should read ALL 348 lines (not just first 8KB)", 348, result.size());
        assertEquals("First line should be correct", "payload_line_1", result.get(0));
        assertEquals("Last line should be correct", "payload_line_348", result.get(347));

        // Verify lines in the middle (after 8KB boundary)
        assertTrue("Line 200 should exist (past 8KB boundary)", result.size() > 200);
        assertEquals("Line 200 should be correct", "payload_line_200", result.get(199));
    }

    /**
     * Test reading file with empty lines
     * NOTE: StringUtils.isNotEmpty() only checks null and length==0, NOT whitespace
     * So lines with only spaces are considered non-empty (this is intentional behavior)
     */
    @Test
    public void testReadStreamToList_WithEmptyLines() {
        // Arrange
        String content = "line1\n\nline2\n  \nline3\n";
        ByteArrayInputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        // Act
        ArrayList<String> result = FileUtils.readStreamToList(is);

        // Assert
        assertNotNull("Result should not be null", result);
        // StringUtils.isNotEmpty("  ") == true (only checks length, not whitespace)
        assertEquals("Should contain 4 lines (including whitespace-only line)", 4, result.size());
        assertEquals("line1", result.get(0));
        assertEquals("line2", result.get(1));
        assertEquals("  ", result.get(2)); // Whitespace-only line is kept
        assertEquals("line3", result.get(3));
    }

    /**
     * Test reading from null input stream
     */
    @Test
    public void testReadStreamToList_NullInputStream() {
        // Act
        ArrayList<String> result = FileUtils.readStreamToList(null);

        // Assert
        assertNull("Result should be null for null input", result);
    }

    /**
     * Test reading from empty stream
     */
    @Test
    public void testReadStreamToList_EmptyStream() {
        // Arrange
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[0]);

        // Act
        ArrayList<String> result = FileUtils.readStreamToList(is);

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Result should be empty", result.isEmpty());
    }

    /**
     * Test readFileToList with actual file (integration test)
     */
    @Test
    public void testReadFileToList_ActualFile() throws IOException {
        // Arrange: Write test content to temp file
        try (FileOutputStream fos = new FileOutputStream(mTempFile)) {
            StringBuilder content = new StringBuilder();
            for (int i = 1; i <= 100; i++) {
                content.append("file_line_").append(i).append("\n");
            }
            fos.write(content.toString().getBytes(StandardCharsets.UTF_8));
        }

        // Act
        ArrayList<String> result = FileUtils.readFileToList(mTempFile);

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Should read all 100 lines", 100, result.size());
        assertEquals("First line should be correct", "file_line_1", result.get(0));
        assertEquals("Last line should be correct", "file_line_100", result.get(99));
    }

    /**
     * Test UTF-8 encoding with Chinese characters
     */
    @Test
    public void testReadStreamToList_ChineseCharacters() {
        // Arrange
        String content = "中文测试1\n英文test2\n混合mixed3\n";
        ByteArrayInputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        // Act
        ArrayList<String> result = FileUtils.readStreamToList(is);

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Should read all 3 lines", 3, result.size());
        assertEquals("Chinese characters should be preserved", "中文测试1", result.get(0));
        assertEquals("English should work", "英文test2", result.get(1));
        assertEquals("Mixed should work", "混合mixed3", result.get(2));
    }
}
