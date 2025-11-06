package burp.onescan;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CharacterEncodingTest {

    @Test
    public void testChineseCharacterHandling() {
        String url = "http://testsite.com/管理员/";
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            assertNotNull(request);
            String u = request.url();
            assertNotNull(u);
            assertTrue(u.contains("%E7%AE%A1%E7%90%86%E5%91%98") || u.contains("管理员"));
        } catch (NullPointerException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "Montoya API not initialized; skipping test.");
        }
    }
}

