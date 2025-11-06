package burp.onescan;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CharacterHeaderEncodingTest {

    @Test
    public void testChineseHeaderHandling() {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl("http://example.com/")
                    .withAddedHeader("X-Name", "管理员");
            assertNotNull(req);
            String v = req.headerValue("X-Name");
            assertNotNull(v);
            assertTrue(v.contains("管理员") || v.contains("%E7%AE%A1%E7%90%86%E5%91%98"));
        } catch (NullPointerException e) {
            Assumptions.assumeTrue(false, "Montoya API not initialized; skipping test.");
        }
    }
}

