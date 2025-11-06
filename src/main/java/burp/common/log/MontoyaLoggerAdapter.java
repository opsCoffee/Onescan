package burp.common.log;

import burp.api.montoya.MontoyaApi;
import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream adapter that forwards writes to Montoya logging API.
 */
public class MontoyaLoggerAdapter extends OutputStream {
    private final MontoyaApi montoya;
    private final boolean error;
    private final StringBuilder buffer = new StringBuilder(256);

    public MontoyaLoggerAdapter(MontoyaApi montoya, boolean error) {
        this.montoya = montoya;
        this.error = error;
    }

    @Override
    public void write(int b) throws IOException {
        char c = (char) (b & 0xFF);
        buffer.append(c);
        if (c == '\n') {
            flushBuffer();
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (b == null || len <= 0) {
            return;
        }
        String s = new String(b, off, len);
        buffer.append(s);
        int idx;
        while ((idx = buffer.indexOf("\n")) >= 0) {
            String line = buffer.substring(0, idx);
            emit(line);
            buffer.delete(0, idx + 1);
        }
    }

    @Override
    public void flush() throws IOException {
        flushBuffer();
    }

    @Override
    public void close() throws IOException {
        flushBuffer();
    }

    private void flushBuffer() {
        if (buffer.length() == 0) {
            return;
        }
        String msg = buffer.toString();
        buffer.setLength(0);
        emit(msg);
    }

    private void emit(String msg) {
        if (montoya == null || msg == null || msg.isEmpty()) {
            return;
        }
        if (error) {
            montoya.logging().logToError(msg);
        } else {
            montoya.logging().logToOutput(msg);
        }
    }
}
