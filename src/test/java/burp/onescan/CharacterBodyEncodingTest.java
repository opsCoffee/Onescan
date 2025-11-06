package burp.onescan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CharacterBodyEncodingTest {

    @Test
    public void testChineseBodyHandling() {
        try {
            String json = "{\"name\":\"管理员\"}";
            HttpRequest req = HttpRequest.httpRequestFromUrl("http://example.com/")
                    .withBody(ByteArray.byteArray(json));
            assertNotNull(req);
            String body = req.bodyToString();
            assertNotNull(body);
            assertTrue(body.contains("管理员") || body.contains("%E7%AE%A1%E7%90%86%E5%91%98"));
        } catch (NullPointerException e) {
            Assumptions.assumeTrue(false, "Montoya API not initialized; skipping test.");
        }
    }
}

