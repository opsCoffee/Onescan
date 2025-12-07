package burp.common.adapter;

import burp.IMessageEditor;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.RawEditor;

import java.awt.*;

/**
 * Adapter to bridge Montoya API's RawEditor to legacy IMessageEditor interface.
 * <p>
 * This adapter allows existing code using IMessageEditor to work with Montoya's RawEditor
 * without modification. The isRequest parameter in setMessage() is ignored since RawEditor
 * doesn't differentiate between request and response.
 * <p>
 * Created for MIGRATE-101-D migration task.
 */
public class RawEditorAdapter implements IMessageEditor {

    private final RawEditor mEditor;

    public RawEditorAdapter(RawEditor editor) {
        this.mEditor = editor;
    }

    @Override
    public Component getComponent() {
        return mEditor.uiComponent();
    }

    @Override
    public void setMessage(byte[] message, boolean isRequest) {
        // isRequest parameter is ignored - RawEditor treats all content as raw bytes
        if (message == null || message.length == 0) {
            mEditor.setContents(ByteArray.byteArray(new byte[0]));
        } else {
            mEditor.setContents(ByteArray.byteArray(message));
        }
    }

    @Override
    public byte[] getMessage() {
        ByteArray contents = mEditor.getContents();
        return contents == null ? new byte[0] : contents.getBytes();
    }

    @Override
    public boolean isMessageModified() {
        return mEditor.isModified();
    }

    @Override
    public byte[] getSelectedData() {
        return mEditor.selection()
                .map(selection -> {
                    ByteArray contents = mEditor.getContents();
                    if (contents == null) {
                        return new byte[0];
                    }
                    int startOffset = selection.offsets().startIndexInclusive();
                    int endOffset = selection.offsets().endIndexExclusive();
                    byte[] allBytes = contents.getBytes();
                    if (startOffset < 0 || endOffset > allBytes.length || startOffset >= endOffset) {
                        return new byte[0];
                    }
                    byte[] selectedBytes = new byte[endOffset - startOffset];
                    System.arraycopy(allBytes, startOffset, selectedBytes, 0, selectedBytes.length);
                    return selectedBytes;
                })
                .orElse(new byte[0]);
    }

    @Override
    public int[] getSelectionBounds() {
        return mEditor.selection()
                .map(selection -> {
                    int start = selection.offsets().startIndexInclusive();
                    int end = selection.offsets().endIndexExclusive();
                    return new int[]{start, end};
                })
                .orElse(null);
    }
}
