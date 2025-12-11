package burp.onescan.ui.tab;

import burp.common.layout.HLayout;
import burp.common.layout.VLayout;
import burp.onescan.common.DataGenerator;
import burp.onescan.common.L;
import burp.onescan.ui.base.BaseTab;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * 数据生成标签页
 * <p>
 * 提供身份证号、银行卡号、手机号、统一社会信用代码、姓名等测试数据的生成功能
 * <p>
 * Created by vaycore on 2024-12-11.
 */
public class DataGeneratorTab extends BaseTab {

    private JTabbedPane mTabbedPane;

    @Override
    protected void initData() {
        // 无需初始化数据
    }

    @Override
    protected void initView() {
        setLayout(new BorderLayout());
        mTabbedPane = new JTabbedPane();
        // 添加子面板
        mTabbedPane.addTab(L.get("generator_idcard"), createIdCardPanel());
        mTabbedPane.addTab(L.get("generator_bankcard"), createBankCardPanel());
        mTabbedPane.addTab(L.get("generator_phone"), createPhonePanel());
        mTabbedPane.addTab(L.get("generator_creditcode"), createCreditCodePanel());
        mTabbedPane.addTab(L.get("generator_name"), createNamePanel());
        add(mTabbedPane, BorderLayout.CENTER);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.generator");
    }


    // ==================== 身份证号生成面板 ====================

    private JPanel createIdCardPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 配置区域
        JPanel configPanel = new JPanel(new HLayout(10));
        configPanel.setBorder(new TitledBorder(L.get("generator_config")));

        // 地区选择
        configPanel.add(new JLabel(L.get("generator_area")));
        JComboBox<String> areaCombo = new JComboBox<>();
        areaCombo.addItem(L.get("generator_random"));
        for (String area : DataGenerator.getAreaCodes()) {
            areaCombo.addItem(area);
        }
        configPanel.add(areaCombo, "150px");

        // 性别选择
        configPanel.add(new JLabel(L.get("generator_gender")));
        JComboBox<String> genderCombo = new JComboBox<>(DataGenerator.getGenders());
        configPanel.add(genderCombo, "80px");

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        configPanel.add(countSpinner, "80px");

        configPanel.add(new JPanel(), "1w");
        panel.add(configPanel, BorderLayout.NORTH);

        // 结果区域
        JTextArea resultArea = createResultArea();
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String areaCode = null;
            if (areaCombo.getSelectedIndex() > 0) {
                String selected = (String) areaCombo.getSelectedItem();
                areaCode = selected.split("-")[0];
            }
            Integer gender = null;
            if (genderCombo.getSelectedIndex() == 1) {
                gender = 1; // 男
            } else if (genderCombo.getSelectedIndex() == 2) {
                gender = 0; // 女
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateIdCard(areaCode, null, gender, count);
        });
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    // ==================== 银行卡号生成面板 ====================

    private JPanel createBankCardPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 配置区域
        JPanel configPanel = new JPanel(new HLayout(10));
        configPanel.setBorder(new TitledBorder(L.get("generator_config")));

        // 卡类型选择
        configPanel.add(new JLabel(L.get("generator_cardtype")));
        JComboBox<String> cardTypeCombo = new JComboBox<>(DataGenerator.getCardTypes());
        configPanel.add(cardTypeCombo, "100px");

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 1000, 1));
        configPanel.add(countSpinner, "80px");

        configPanel.add(new JPanel(), "1w");
        panel.add(configPanel, BorderLayout.NORTH);

        // 结果区域
        JTextArea resultArea = createResultArea();
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String cardType = (String) cardTypeCombo.getSelectedItem();
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateBankCard(cardType, count);
        });
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }


    // ==================== 手机号生成面板 ====================

    private JPanel createPhonePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 配置区域
        JPanel configPanel = new JPanel(new HLayout(10));
        configPanel.setBorder(new TitledBorder(L.get("generator_config")));

        // 运营商选择
        configPanel.add(new JLabel(L.get("generator_carrier")));
        JComboBox<String> carrierCombo = new JComboBox<>();
        carrierCombo.addItem(L.get("generator_random"));
        for (String carrier : DataGenerator.getCarriers()) {
            carrierCombo.addItem(carrier);
        }
        configPanel.add(carrierCombo, "120px");

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        configPanel.add(countSpinner, "80px");

        configPanel.add(new JPanel(), "1w");
        panel.add(configPanel, BorderLayout.NORTH);

        // 结果区域
        JTextArea resultArea = createResultArea();
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            String carrier = null;
            if (carrierCombo.getSelectedIndex() > 0) {
                carrier = (String) carrierCombo.getSelectedItem();
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generatePhone(carrier, count);
        });
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    // ==================== 统一社会信用代码生成面板 ====================

    private JPanel createCreditCodePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 配置区域
        JPanel configPanel = new JPanel(new HLayout(10));
        configPanel.setBorder(new TitledBorder(L.get("generator_config")));

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        configPanel.add(countSpinner, "80px");

        configPanel.add(new JPanel(), "1w");
        panel.add(configPanel, BorderLayout.NORTH);

        // 结果区域
        JTextArea resultArea = createResultArea();
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateCreditCode(count);
        });
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    // ==================== 姓名生成面板 ====================

    private JPanel createNamePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 配置区域
        JPanel configPanel = new JPanel(new HLayout(10));
        configPanel.setBorder(new TitledBorder(L.get("generator_config")));

        // 性别选择
        configPanel.add(new JLabel(L.get("generator_gender")));
        JComboBox<String> genderCombo = new JComboBox<>(DataGenerator.getGenders());
        configPanel.add(genderCombo, "80px");

        // 生成数量
        configPanel.add(new JLabel(L.get("generator_count")));
        JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        configPanel.add(countSpinner, "80px");

        configPanel.add(new JPanel(), "1w");
        panel.add(configPanel, BorderLayout.NORTH);

        // 结果区域
        JTextArea resultArea = createResultArea();
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel(resultArea, () -> {
            Integer gender = null;
            if (genderCombo.getSelectedIndex() == 1) {
                gender = 1; // 男
            } else if (genderCombo.getSelectedIndex() == 2) {
                gender = 0; // 女
            }
            int count = (Integer) countSpinner.getValue();
            return DataGenerator.generateName(gender, count);
        });
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }


    // ==================== 通用组件创建方法 ====================

    /**
     * 创建结果显示区域
     */
    private JTextArea createResultArea() {
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        textArea.setEditable(false);
        return textArea;
    }

    /**
     * 创建按钮面板
     *
     * @param resultArea 结果显示区域
     * @param generator  数据生成器
     */
    private JPanel createButtonPanel(JTextArea resultArea, DataGeneratorCallback generator) {
        JPanel panel = new JPanel(new HLayout(10));
        panel.setBorder(new EmptyBorder(5, 0, 0, 0));

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

        panel.add(new JPanel(), "1w");
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
