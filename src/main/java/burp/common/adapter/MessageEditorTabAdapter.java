package burp.common.adapter;

import burp.IMessageEditorTab;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.onescan.info.OneScanInfoTab;

import java.awt.*;

/**
 * Adapter to bridge OneScanInfoTab (Montoya API) to IMessageEditorTab interface.
 * <p>
 * This adapter allows OneScanInfoTab (which no longer implements IMessageEditorTab)
 * to work with legacy code that expects IMessageEditorTab interface.
 * <p>
 * Created for MIGRATE-303-C migration task.
 */
public class MessageEditorTabAdapter implements IMessageEditorTab {

    private final OneScanInfoTab mTab;

    public MessageEditorTabAdapter(OneScanInfoTab tab) {
        this.mTab = tab;
    }

    @Override
    public String getTabCaption() {
        return mTab.getCaption();
    }

    @Override
    public Component getUiComponent() {
        return mTab.getUiComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // OneScanInfoTab doesn't have direct access to the current message,
        // so we return true to always show the tab
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        // OneScanInfoTab expects HttpRequestResponse, not raw bytes
        // This method is a no-op since OneScanInfoTab is updated through other means
    }

    @Override
    public byte[] getMessage() {
        // OneScanInfoTab doesn't support getting the message back
        return new byte[0];
    }

    @Override
    public boolean isModified() {
        return mTab.isModified();
    }

    @Override
    public byte[] getSelectedData() {
        // OneScanInfoTab doesn't support selection
        return null;
    }
}
