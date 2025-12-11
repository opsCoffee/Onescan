package burp.onescan.ui.tab;

import burp.common.layout.HLayout;
import burp.common.layout.VFlowLayout;
import burp.onescan.common.DataGenerator;
import burp.onescan.common.L;
import burp.onescan.ui.widget.DividerLine;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * 数据生成标签页
 * <p>
 * 提供身份证号、银行卡号、手机号、统一社会信用代码、姓名等测试数据的生成功能
 * <p>
 * Created by vaycore on 2024-12-11.
 */
public class DataGeneratorTab extends JTabbedPane {

    public DataGeneratorTab() {
        initView();
    }

    public String getTitleName() {
        return L.get("tab_name.generator");
    }

    private void initView() {
        // 添加子面板（使用 JScrollPane 包装）
        addGeneratorTab(L.get("generator_idcard"), createIdCardPanel());
        addGeneratorTab(L.get("generator_bankcard"), createBankCardPanel());
        addGeneratorTab(L.get("generator_phone"), createPhonePanel());
        addGeneratorTab(L.get("generator_creditcode"), createCreditCodePanel());
        addGeneratorTab(L.get("generator_name"), createNamePanel());
    }

    /**
     * 添加生成器子面板
     */
    private void addGeneratorTab(String title, JPanel panel) {
        JScrollPane scrollPane = new JScrollPane(panel);
        scrollPane.getVerticalScrollBar().setUnitIncrement(30);
        scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
        addTab(title, scrollPane);
    }


    // ==================== 通用样式方法 ====================

    /**
     * 创建基础面板（使用项目统一的 VFlowLayout 布局）
     */
    private JPanel createBasePanel() {
        JPanel panel = new JPanel();
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        panel.setLayout(new VFlowLayout());
        return panel;
    }

    /**
     * 添加配置项标题
     */
    private void addTitle(JPanel panel, String title) {
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(16f).deriveFont(Font.BOLD));
        label.setBorder(new EmptyBorder(5, 3, 5, 0));
        label.setForeground(Color.decode("#FF6633"));
        panel.add(label);
    }

    /**
     * 添加配置项副标题
     */
    private void addSubTitle(JPanel panel, String subTitle) {
        JLabel label = new JLabel(subTitle);
        label.setBorder(new EmptyBorder(0, 3, 5, 0));
        panel.add(label);
    }

    /**
     * 添加分隔线
     */
    private void addDivider(JPanel panel) {
        panel.add(new JPanel(), "10px");
        panel.add(DividerLine.h());
    }

    /**
     * 创建结果显示区域
     */
    private JTextArea createResultArea() {
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        textArea.setEditable(false);
        textArea.setRows(15);
        return textArea;
    }

    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel(JTextArea resultArea, DataGeneratorCallback generator) {
        JPanel panel = new JPanel(new HLayout(5));

        // 生成按钮
        JButton generateBtn = new JButton(L.get("generator_generate"));
        generateBtn.addActionListener(e -> {
            List<String> data = generator.generate();
            resultArea.setText(String.join("\n", data));
        });
        panel.add(generateBtn);

        // 复制按钮
        JButton copyBtn = new JButton(L.get("generator_copy"));
        copyBtn.addActionListener(e -> {
            String text = resultArea.getText();
            if (!text.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(text), null);
            }
        });
        panel.add(copyBtn);

        // 清空按钮
        JButton clearBtn = new JButton(L.get("generator_clear"));
        clearBtn.addActionListener(e -> resultArea.setText(""));
        panel.add(clearBtn);

        return panel;
    }


    // ==================== 身份证号生成面板 ====================

    private JPanel createIdCardPanel() {
        JPanel panel = createBasePanel();

        // 配置区域标题
        addTitle(panel, L.get("generator_idcard"));
        addSubTitle(panel, L.get("generator_idcard_desc"));

        // 配置选项
        JPanel configPanel = new JPanel(new HLayout(10));

        // 地区选择
        configPanel.add(new JLabel(L.get("generator_area")));
        JComboBox<String> areaCombo = new JComboBox<>();
        areaCombo.addItem(L.get("generator_random"));
        for (String area : DataGenerator.getAreaCodes()) {
            areaCombo.addItem(area);
        }
        areaCombo.setPreferredSize(new Dimension(180, 25));
        configPanel.add(areaCombo);

        // 性别选择
        configPanel.add(new JLabel(L.get("generator_gender")));
        JComboBox<String> genderCombo = new JComboBox<>(DataGenerator.getGenders());
        genderCombo.setPreferredSize(new Dimension(80, 25));
        configPanel.add(genderCombo);

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        countSpinner.setPreferredSize(new Dimension(80, 25));
        configPanel.add(countSpinner);

        panel.add(configPanel);
        addDivider(panel);

        // 结果区域标题
        addTitle(panel, L.get("generator_result"));

        // 结果显示
        JTextArea resultArea = createResultArea();
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        panel.add(scrollPane);

        // 按钮面板
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String areaCode = null;
            if (areaCombo.getSelectedIndex() > 0) {
                String selected = (String) areaCombo.getSelectedItem();
                areaCode = selected.split("-")[0];
            }
            Integer gender = null;
            if (genderCombo.getSelectedIndex() == 1) {
                gender = 1;
            } else if (genderCombo.getSelectedIndex() == 2) {
                gender = 0;
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateIdCard(areaCode, null, gender, count);
        });
        panel.add(buttonPanel);

        return panel;
    }

    // ==================== 银行卡号生成面板 ====================

    private JPanel createBankCardPanel() {
        JPanel panel = createBasePanel();

        addTitle(panel, L.get("generator_bankcard"));
        addSubTitle(panel, L.get("generator_bankcard_desc"));

        JPanel configPanel = new JPanel(new HLayout(10));

        // 卡类型选择
        configPanel.add(new JLabel(L.get("generator_cardtype")));
        JComboBox<String> cardTypeCombo = new JComboBox<>(DataGenerator.getCardTypes());
        cardTypeCombo.setPreferredSize(new Dimension(100, 25));
        configPanel.add(cardTypeCombo);

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 1000, 1));
        countSpinner.setPreferredSize(new Dimension(80, 25));
        configPanel.add(countSpinner);

        panel.add(configPanel);
        addDivider(panel);

        addTitle(panel, L.get("generator_result"));

        JTextArea resultArea = createResultArea();
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        panel.add(scrollPane);

        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String cardType = (String) cardTypeCombo.getSelectedItem();
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateBankCard(cardType, count);
        });
        panel.add(buttonPanel);

        return panel;
    }


    // ==================== 手机号生成面板 ====================

    private JPanel createPhonePanel() {
        JPanel panel = createBasePanel();

        addTitle(panel, L.get("generator_phone"));
        addSubTitle(panel, L.get("generator_phone_desc"));

        JPanel configPanel = new JPanel(new HLayout(10));

        // 运营商选择
        configPanel.add(new JLabel(L.get("generator_carrier")));
        JComboBox<String> carrierCombo = new JComboBox<>();
        carrierCombo.addItem(L.get("generator_random"));
        for (String carrier : DataGenerator.getCarriers()) {
            carrierCombo.addItem(carrier);
        }
        carrierCombo.setPreferredSize(new Dimension(120, 25));
        configPanel.add(carrierCombo);

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        countSpinner.setPreferredSize(new Dimension(80, 25));
        configPanel.add(countSpinner);

        panel.add(configPanel);
        addDivider(panel);

        addTitle(panel, L.get("generator_result"));

        JTextArea resultArea = createResultArea();
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        panel.add(scrollPane);

        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String carrier = null;
            if (carrierCombo.getSelectedIndex() > 0) {
                carrier = (String) carrierCombo.getSelectedItem();
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generatePhone(carrier, count);
        });
        panel.add(buttonPanel);

        return panel;
    }

    // ==================== 统一社会信用代码生成面板 ====================

    private JPanel createCreditCodePanel() {
        JPanel panel = createBasePanel();

        addTitle(panel, L.get("generator_creditcode"));
        addSubTitle(panel, L.get("generator_creditcode_desc"));

        JPanel configPanel = new JPanel(new HLayout(10));

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        countSpinner.setPreferredSize(new Dimension(80, 25));
        configPanel.add(countSpinner);

        panel.add(configPanel);
        addDivider(panel);

        addTitle(panel, L.get("generator_result"));

        JTextArea resultArea = createResultArea();
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        panel.add(scrollPane);

        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateCreditCode(count);
        });
        panel.add(buttonPanel);

        return panel;
    }

    // ==================== 姓名生成面板 ====================

    private JPanel createNamePanel() {
        JPanel panel = createBasePanel();

        addTitle(panel, L.get("generator_name"));
        addSubTitle(panel, L.get("generator_name_desc"));

        JPanel configPanel = new JPanel(new HLayout(10));

        // 性别选择
        configPanel.add(new JLabel(L.get("generator_gender")));
        JComboBox<String> genderCombo = new JComboBox<>(DataGenerator.getGenders());
        genderCombo.setPreferredSize(new Dimension(80, 25));
        configPanel.add(genderCombo);

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        countSpinner.setPreferredSize(new Dimension(80, 25));
        configPanel.add(countSpinner);

        panel.add(configPanel);
        addDivider(panel);

        addTitle(panel, L.get("generator_result"));

        JTextArea resultArea = createResultArea();
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        panel.add(scrollPane);

        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            Integer gender = null;
            if (genderCombo.getSelectedIndex() == 1) {
                gender = 1;
            } else if (genderCombo.getSelectedIndex() == 2) {
                gender = 0;
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateName(gender, count);
        });
        panel.add(buttonPanel);

        return panel;
    }

    /**
     * 数据生成回调接口
     */
    @FunctionalInterface
    private interface DataGeneratorCallback {
        List<String> generate();
    }
}
