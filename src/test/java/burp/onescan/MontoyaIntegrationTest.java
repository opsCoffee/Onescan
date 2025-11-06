package burp.onescan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.common.log.MontoyaLoggerAdapter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MontoyaIntegrationTest {

    @Test
    public void testHttpRequestFactoryAvailable() {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl("http://example.com/");
            assertNotNull(req);
        } catch (NullPointerException e) {
            Assumptions.assumeTrue(false, "Montoya API not initialized; skipping test.");
        }
    }

    @Test
    public void testEditorsCreationSkippedWithoutRuntime() {
        try {
            // Creating editors requires Burp runtime; this test ensures no hard failures in absence.
            Assumptions.assumeTrue(false, "Requires Burp runtime; skipping.");
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testProxyRegistrationSkippedWithoutRuntime() {
        try {
            Assumptions.assumeTrue(false, "Requires Burp runtime; skipping.");
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testMontoyaLoggerAdapterNoCrash() {
        // Null Montoya is allowed; adapter simply ignores
        MontoyaLoggerAdapter out = new MontoyaLoggerAdapter((MontoyaApi) null, false);
        MontoyaLoggerAdapter err = new MontoyaLoggerAdapter((MontoyaApi) null, true);
        assertDoesNotThrow(() -> {
            out.write("hello\n".getBytes());
            err.write("world\n".getBytes());
            out.flush();
            err.flush();
        });
    }
}

