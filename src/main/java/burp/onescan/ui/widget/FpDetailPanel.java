package burp.onescan.ui.widget;

import burp.common.helper.UIHelper;
import burp.common.layout.HLayout;
import burp.common.layout.VFlowLayout;
import burp.common.layout.VLayout;
import burp.common.log.Logger;
import burp.common.utils.ClassUtils;
import burp.common.utils.StringUtils;
import burp.common.widget.HintTextField;
import burp.onescan.bean.FpData;
import burp.onescan.bean.FpRule;
import burp.onescan.common.L;
import burp.onescan.manager.FpManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Vector;

/**
 * 指纹详情
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpDetailPanel extends JPanel implements ActionListener {

    private final boolean hasCreate;
    private final FpData mData;
    private JComboBox<String> mColorComboBox;
    private DefaultListModel<String> mRulesListModel;
    private JList<String> mRulesListView;
    private JPanel mParamsPanel; // deprecated in new format
    private JScrollPane mParamsScrollPanel; // deprecated in new format
    private Vector<String> mParamNameItems; // deprecated in new format
    private JTextField mNameText;
    private JCheckBox mEnabledCheckBox;

    public FpDetailPanel() {
        this(null);
    }

    public FpDetailPanel(FpData data) {
        if (data == null) {
            data = new FpData();
            this.hasCreate = true;
        } else {
            data = ClassUtils.deepCopy(data);
            this.hasCreate = false;
        }
        mData = data;
        this.initView();
        this.setupData();
    }

    private void initView() {
        setLayout(new VLayout(3));
        setPreferredSize(new Dimension(400, 450));
        addEnabledPanel();
        addNamePanel();
        addColorPanel();
        addRulesPanel();
    }

    private void addNamePanel() {
        JPanel panel = new JPanel(new HLayout(2, true));
        panel.add(new JLabel(L.get("fingerprint_detail.name") + "："), "78px");
        mNameText = new HintTextField();
        panel.add(mNameText, "1w");
        add(panel);
    }

    private void addEnabledPanel() {
        JPanel panel = new JPanel(new HLayout(2, true));
        panel.add(new JLabel(L.get("fingerprint_detail.enabled") + "："), "78px");
        mEnabledCheckBox = new JCheckBox();
        mEnabledCheckBox.setSelected(true);
        panel.add(mEnabledCheckBox, "1w");
        add(panel);
    }

    private void setupData() {
        if (this.hasCreate) {
            return;
        }
        // Name 填充（从第一个列的参数中读出值）
        ArrayList<FpData.Param> params = mData.getParams();
        if (params != null) {
            String columnId = FpManager.getColumnId(0);
            if (columnId != null) {
                for (FpData.Param param : params) {
                    if (param != null && columnId.equals(param.getK())) {
                        mNameText.setText(param.getV());
                        break;
                    }
                }
            }
        }
        // 填充颜色数据
        mColorComboBox.setSelectedItem(mData.getColor());
        // 是否启用
        mEnabledCheckBox.setSelected(mData.isEnabled());
        // 填充指纹规则
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        for (ArrayList<FpRule> fpRules : rules) {
            String ruleItem = this.parseFpRulesToStr(fpRules);
            mRulesListModel.addElement(ruleItem);
        }
    }

    /**
     * 添加指纹参数布局
     */
    private void addParamsPanel() {
        // 新格式不再使用参数面板，保留空实现以兼容布局调用
    }

    /**
     * 添加参数
     */
    private void doAddParam() {
        addParamItem(null);
        UIHelper.refreshUI(mParamsScrollPanel);
    }

    private void addParamItem(FpData.Param param) {
        String paramName = "";
        String paramValue = "";
        if (param != null) {
            // 存储的是指纹字段 ID 值，需要转换
            paramName = FpManager.findColumnNameById(param.getK());
            paramValue = param.getV();
        }
        // 布局
        JPanel panel = new JPanel(new HLayout(5, true));
        mParamsPanel.add(panel);
        // 参数名组件
        JComboBox<String> paramNameBox = new JComboBox<>(genParamNameItems());
        paramNameBox.setSelectedItem(paramName);
        panel.add(paramNameBox);
        // 参数值输入框组件
        HintTextField paramValueInput = new HintTextField(paramValue);
        paramValueInput.setHintText(L.get("fingerprint_detail.param_value"));
        panel.add(paramValueInput, "1w");
        // 删除按钮组件
        JButton delBtn = new JButton("X");
        panel.add(delBtn, "40px");
        // 事件处理
        delBtn.addActionListener((e) -> {
            mParamsPanel.remove(panel);
            UIHelper.refreshUI(mParamsScrollPanel);
        });
    }

    /**
     * 生成参数名 Item 选项
     */
    private Vector<String> genParamNameItems() {
        if (mParamNameItems != null) {
            return mParamNameItems;
        }
        Vector<String> result = new Vector<>();
        result.add(L.get("fingerprint_detail.param_name"));
        List<String> list = FpManager.getColumnNames();
        result.addAll(list);
        mParamNameItems = result;
        return result;
    }

    /**
     * 添加指纹颜色布局
     */
    private void addColorPanel() {
        String label = L.get("fingerprint_table_columns.color");
        JPanel panel = new JPanel(new HLayout(2, true));
        panel.add(new JLabel(label + "："), "78px");
        mColorComboBox = new JComboBox<>(FpManager.sColorNames);
        panel.add(mColorComboBox, "1w");
        add(panel);
    }

    /**
     * 添加指纹规则布局
     */
    private void addRulesPanel() {
        add(new JLabel(L.get("fingerprint_detail.rules_border_title")));
        // 指纹规则
        JPanel panel = new JPanel(new HLayout(5));
        panel.add(createRulesLeftPanel(), "120px");
        mRulesListModel = new DefaultListModel<>();
        mRulesListView = new JList<>(mRulesListModel);
        UIHelper.setListCellRenderer(mRulesListView);
        JScrollPane scrollPane = new JScrollPane(mRulesListView);
        panel.add(scrollPane, "1w");
        add(panel, "1w");

        // 表达式预览（只读）
        add(new JLabel(L.get("fingerprint_detail.rules_preview")));
        JTextArea preview = new JTextArea();
        preview.setEditable(false);
        preview.setLineWrap(true);
        preview.setWrapStyleWord(true);
        preview.setRows(3);
        add(new JScrollPane(preview), "100px");
        mExprPreview = preview;
    }

    /**
     * 创建指纹规则功能按钮布局
     */
    private JPanel createRulesLeftPanel() {
        JPanel panel = new JPanel(new VLayout(5));
        panel.add(new JLabel(L.get("fingerprint_detail.rules_panel_title")));
        addRulesLeftButton(panel, L.get("add"), "add-item");
        addRulesLeftButton(panel, L.get("edit"), "edit-item");
        addRulesLeftButton(panel, L.get("delete"), "delete-item");
        addRulesLeftButton(panel, L.get("up"), "up-item");
        addRulesLeftButton(panel, L.get("down"), "down-item");
        return panel;
    }

    /**
     * 添加指纹规则功能按钮
     */
    private void addRulesLeftButton(JPanel panel, String text, String action) {
        JButton btn = new JButton(text);
        btn.setActionCommand(action);
        btn.addActionListener(this);
        panel.add(btn);
    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        boolean needSave = false;
        
        if ("add-item".equals(action)) {
            FpRulesPanel panel = new FpRulesPanel();
            ArrayList<FpRule> fpRules = panel.showDialog(this);
            if (fpRules != null) {
                rules.add(fpRules);
                String rulesText = this.parseFpRulesToStr(fpRules);
                int idx = mRulesListModel.getSize() + 1;
                mRulesListModel.addElement(L.get("fingerprint_detail.rules_group_prefix", idx) + ": " + rulesText);
                refreshExpressionPreview();
                needSave = true;
            }
            if (needSave) {
                saveCurrentData();
            }
            return;
        }
        int index = mRulesListView.getSelectedIndex();
        if (index < 0 || index >= rules.size()) {
            return;
        }
        switch (action) {
            case "edit-item":
                FpRulesPanel panel = new FpRulesPanel(rules.get(index));
                ArrayList<FpRule> fpRules = panel.showDialog(this);
                if (fpRules != null) {
                    rules.set(index, fpRules);
                    String rulesText = this.parseFpRulesToStr(fpRules);
                    mRulesListModel.setElementAt(L.get("fingerprint_detail.rules_group_prefix", index + 1) + ": " + rulesText, index);
                    refreshExpressionPreview();
                    needSave = true;
                }
                break;
            case "delete-item":
                int ret = UIHelper.showOkCancelDialog(
                        L.get("fingerprint_detail.confirm_delete_rule_hint"), this);
                if (ret == 0) {
                    mRulesListModel.removeElementAt(index);
                    rules.remove(index);
                    refreshExpressionPreview();
                    needSave = true;
                }
                break;
            case "up-item":
                int upIndex = index - 1;
                if (upIndex >= 0) {
                    doMoveItem(rules, index, upIndex);
                    refreshExpressionPreview();
                    needSave = true;
                }
                break;
            case "down-item":
                int downIndex = index + 1;
                if (downIndex < mRulesListModel.size()) {
                    doMoveItem(rules, index, downIndex);
                    refreshExpressionPreview();
                    needSave = true;
                }
                break;
        }
        
        if (needSave) {
            saveCurrentData();
        }
    }

    /**
     * 移动 Item 位置
     *
     * @param rules   指纹规则列表
     * @param index   当前位置下标
     * @param toIndex 目标位置下标
     */
    private void doMoveItem(ArrayList<ArrayList<FpRule>> rules, int index, int toIndex) {
        String temp = mRulesListModel.get(index);
        mRulesListModel.setElementAt(mRulesListModel.get(toIndex), index);
        mRulesListModel.setElementAt(temp, toIndex);
        mRulesListView.setSelectedIndex(toIndex);
        // 同步更新
        ArrayList<FpRule> tempRule = rules.get(index);
        rules.set(index, rules.get(toIndex));
        rules.set(toIndex, tempRule);
        // 重标注序号
        for (int i = 0; i < mRulesListModel.getSize(); i++) {
            String text = mRulesListModel.get(i);
            int pos = text.indexOf(": ");
            String expr = pos >= 0 ? text.substring(pos + 2) : text;
            mRulesListModel.set(i, L.get("fingerprint_detail.rules_group_prefix", i + 1) + ": " + expr);
        }
    }

    /**
     * 保存当前数据到配置文件
     * 当规则发生变化时立即保存，确保数据不丢失
     */
    private void saveCurrentData() {
        if (hasCreate) {
            // 新建指纹时不需要立即保存，等用户确认后再保存
            return;
        }
        
        try {
            // 查找当前指纹在列表中的位置
            List<FpData> allData = FpManager.getList();
            for (int i = 0; i < allData.size(); i++) {
                FpData existingData = allData.get(i);
                // 通过比较参数来识别是否为同一个指纹（因为FpData可能被深拷贝）
                if (isSameFingerprint(existingData, mData)) {
                    // 更新指纹数据（这会触发FpManager的保存逻辑）
                    FpManager.setItem(i, mData);
                    Logger.debug("指纹规则已实时保存: 索引=%d", i);
                    break;
                }
            }
        } catch (Exception e) {
            Logger.error("实时保存指纹规则失败: %s", e.getMessage());
        }
    }

    /**
     * 判断两个指纹数据是否为同一个指纹
     * 通过比较参数列表来识别
     */
    private boolean isSameFingerprint(FpData data1, FpData data2) {
        if (data1 == null || data2 == null) {
            return false;
        }
        
        ArrayList<FpData.Param> params1 = data1.getParams();
        ArrayList<FpData.Param> params2 = data2.getParams();
        
        if (params1 == null && params2 == null) {
            return true;
        }
        if (params1 == null || params2 == null) {
            return false;
        }
        if (params1.size() != params2.size()) {
            return false;
        }
        
        // 比较所有参数
        for (int i = 0; i < params1.size(); i++) {
            FpData.Param p1 = params1.get(i);
            FpData.Param p2 = params2.get(i);
            if (p1 == null && p2 == null) {
                continue;
            }
            if (p1 == null || p2 == null) {
                return false;
            }
            if (!Objects.equals(p1.getK(), p2.getK()) || !Objects.equals(p1.getV(), p2.getV())) {
                return false;
            }
        }
        
        return true;
    }

    private transient JTextArea mExprPreview;

    private void refreshExpressionPreview() {
        if (mExprPreview == null) return;
        int size = mRulesListModel.getSize();
        if (size <= 0) {
            mExprPreview.setText("");
            return;
        }
        java.util.List<String> groups = new java.util.ArrayList<>();
        for (int i = 0; i < size; i++) {
            String text = mRulesListModel.get(i);
            int pos = text.indexOf(": ");
            groups.add(pos >= 0 ? text.substring(pos + 2) : text);
        }
        String expr = "(" + StringUtils.join(groups, ") OR (") + ")";
        mExprPreview.setText(expr);
    }

    /**
     * 解析指纹规则数据，转换为表达式格式
     *
     * @param rules 指纹规则数据
     * @return 失败返回空字符串
     */
    private String parseFpRulesToStr(ArrayList<FpRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return "";
        }
        ArrayList<String> ruleItems = new ArrayList<>();
        for (FpRule rule : rules) {
            String content = rule.getContent().replace("\"", "\\\"");
            String sb = rule.getDataSource() + "." + rule.getField() + "." + rule.getMethod() + "(\"" + content + "\")";
            ruleItems.add(sb);
        }
        return StringUtils.join(ruleItems, " && ");
    }

    /**
     * 检测指纹参数列表是否已包含指纹字段 ID 值
     *
     * @param params   指纹参数列表
     * @param columnId 指纹字段 ID 值
     * @return true=包含；false=不包含
     */
    private boolean containsColumnId(ArrayList<FpData.Param> params, String columnId) {
        if (StringUtils.isEmpty(columnId) || params == null || params.isEmpty()) {
            return false;
        }
        for (FpData.Param param : params) {
            if (param != null && columnId.equals(param.getK())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取对话框标题
     */
    private String getDialogTitle() {
        if (hasCreate) {
            return L.get("fingerprint_detail.add_title");
        } else {
            return L.get("fingerprint_detail.edit_title");
        }
    }

    /**
     * 显示添加/编辑指纹对话框
     *
     * @return 返回添加/编辑完成的指纹数据实例；取消添加/编辑时返回null
     */
    public FpData showDialog() {
        int state = UIHelper.showCustomDialog(getDialogTitle(), this);
        if (state != JOptionPane.OK_OPTION) {
            return null;
        }
        // 设置 Name -> 第一个列（如 Notes）
        ArrayList<FpData.Param> params = new ArrayList<>();
        String nameValue = mNameText == null ? null : mNameText.getText();
        String firstColumnId = FpManager.getColumnId(0);
        if (StringUtils.isNotEmpty(nameValue) && firstColumnId != null) {
            params.add(new FpData.Param(firstColumnId, nameValue));
        }
        mData.setParams(params);
        // 设置指纹颜色
        String color = String.valueOf(mColorComboBox.getSelectedItem());
        mData.setColor(color);
        // 设置启用状态
        mData.setEnabled(mEnabledCheckBox.isSelected());
        // 检测指纹规则是否为空
        if (mData.getRules().isEmpty()) {
            String message = L.get("fingerprint_detail.rules_empty_hint");
            UIHelper.showTipsDialog(message, this);
            return showDialog();
        }
        // 刷新预览
        refreshExpressionPreview();
        return mData;
    }
}
