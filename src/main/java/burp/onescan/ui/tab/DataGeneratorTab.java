package burp.onescan.ui.tab;

import burp.common.layout.HLayout;
import burp.onescan.common.DataGenerator;
import burp.onescan.common.L;
import burp.onescan.ui.base.BaseConfigTab;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 数据生成标签页
 * <p>
 * 提供身份证号、银行卡号、手机号、统一社会信用代码、组织机构代码、纳税人识别号、姓名等测试数据的生成功能
 * <p>
 * Created by vaycore on 2024-12-11.
 */
public class DataGeneratorTab extends BaseConfigTab {

    // 数据类型复选框
    private Map<String, JCheckBox> mDataTypeCheckBoxes;

    // 配置组件
    private JComboBox<String> mAreaCombo;
    private JComboBox<String> mGenderCombo;
    private JComboBox<String> mCardTypeCombo;
    private JComboBox<String> mCarrierCombo;
    private JSpinner mCountSpinner;

    // 结果显示
    private JTextArea mResultArea;

    @Override
    protected void initData() {
        // 必须在 super.initData() 之前初始化成员变量，因为父类构造函数会调用 initView()
        mDataTypeCheckBoxes = new LinkedHashMap<>();
        super.initData();
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.generator");
    }

    @Override
    protected void initView() {
        // 数据类型选择区域
        addConfigItem(L.get("generator_select_type"), L.get("generator_select_type_desc"),
                createDataTypePanel(), createSelectButtonPanel());

        // 配置选项区域
        addConfigItem(L.get("generator_config"), L.get("generator_config_desc"),
                createConfigRow1(), createConfigRow2());

        // 结果显示区域
        addConfigItem(L.get("generator_result"), null, createResultPanel(), createActionButtonPanel());
    }


    /**
     * 创建数据类型选择面板
     */
    private JPanel createDataTypePanel() {
        JPanel panel = new JPanel(new GridLayout(2, 4, 15, 8));

        // 第一行：身份证、银行卡、手机号、姓名
        panel.add(createCheckBox("idcard", L.get("generator_idcard"), true));
        panel.add(createCheckBox("bankcard", L.get("generator_bankcard"), false));
        panel.add(createCheckBox("phone", L.get("generator_phone"), false));
        panel.add(createCheckBox("name", L.get("generator_name"), false));

        // 第二行：统一社会信用代码、组织机构代码、纳税人识别号、占位
        panel.add(createCheckBox("creditcode", L.get("generator_creditcode"), false));
        panel.add(createCheckBox("orgcode", L.get("generator_orgcode"), false));
        panel.add(createCheckBox("taxpayerid", L.get("generator_taxpayerid"), false));
        panel.add(new JLabel()); // 占位

        return panel;
    }

    /**
     * 创建选择按钮面板（全选/取消全选）
     */
    private JPanel createSelectButtonPanel() {
        JPanel panel = new JPanel(new HLayout(5));

        JButton selectAllBtn = new JButton(L.get("generator_select_all"));
        selectAllBtn.addActionListener(e -> {
            for (JCheckBox checkBox : mDataTypeCheckBoxes.values()) {
                checkBox.setSelected(true);
            }
        });
        panel.add(selectAllBtn);

        JButton deselectAllBtn = new JButton(L.get("generator_deselect_all"));
        deselectAllBtn.addActionListener(e -> {
            for (JCheckBox checkBox : mDataTypeCheckBoxes.values()) {
                checkBox.setSelected(false);
            }
        });
        panel.add(deselectAllBtn);

        return panel;
    }

    /**
     * 创建复选框
     */
    private JCheckBox createCheckBox(String key, String text, boolean selected) {
        JCheckBox checkBox = new JCheckBox(text, selected);
        mDataTypeCheckBoxes.put(key, checkBox);
        return checkBox;
    }

    /**
     * 创建配置选项第一行（地区、性别）
     */
    private JPanel createConfigRow1() {
        JPanel panel = new JPanel(new HLayout(10));

        // 地区选择（身份证用）
        panel.add(new JLabel(L.get("generator_area")));
        mAreaCombo = new JComboBox<>();
        mAreaCombo.addItem(L.get("generator_random"));
        for (String area : DataGenerator.getAreaCodes()) {
            mAreaCombo.addItem(area);
        }
        mAreaCombo.setPreferredSize(new Dimension(180, 25));
        panel.add(mAreaCombo);

        // 性别选择（身份证、姓名用）
        panel.add(new JLabel(L.get("generator_gender")));
        mGenderCombo = new JComboBox<>(DataGenerator.getGenders());
        mGenderCombo.setPreferredSize(new Dimension(80, 25));
        panel.add(mGenderCombo);

        return panel;
    }

    /**
     * 创建配置选项第二行（卡类型、运营商、数量）
     */
    private JPanel createConfigRow2() {
        JPanel panel = new JPanel(new HLayout(10));

        // 卡类型选择（银行卡用）
        panel.add(new JLabel(L.get("generator_cardtype")));
        mCardTypeCombo = new JComboBox<>(DataGenerator.getCardTypes());
        mCardTypeCombo.setPreferredSize(new Dimension(100, 25));
        panel.add(mCardTypeCombo);

        // 运营商选择（手机号用）
        panel.add(new JLabel(L.get("generator_carrier")));
        mCarrierCombo = new JComboBox<>();
        mCarrierCombo.addItem(L.get("generator_random"));
        for (String carrier : DataGenerator.getCarriers()) {
            mCarrierCombo.addItem(carrier);
        }
        mCarrierCombo.setPreferredSize(new Dimension(120, 25));
        panel.add(mCarrierCombo);

        // 生成数量
        panel.add(new JLabel(L.get("generator_count")));
        mCountSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        mCountSpinner.setPreferredSize(new Dimension(80, 25));
        panel.add(mCountSpinner);

        return panel;
    }

    /**
     * 创建结果显示面板
     */
    private JScrollPane createResultPanel() {
        mResultArea = new JTextArea();
        mResultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        mResultArea.setEditable(false);
        mResultArea.setRows(15);

        JScrollPane scrollPane = new JScrollPane(mResultArea);
        scrollPane.setPreferredSize(new Dimension(0, 300));
        return scrollPane;
    }

    /**
     * 创建操作按钮面板（生成、复制、清空）
     */
    private JPanel createActionButtonPanel() {
        JPanel panel = new JPanel(new HLayout(5));

        // 生成按钮
        JButton generateBtn = new JButton(L.get("generator_generate"));
        generateBtn.addActionListener(e -> generateData());
        panel.add(generateBtn);

        // 复制按钮
        JButton copyBtn = new JButton(L.get("generator_copy"));
        copyBtn.addActionListener(e -> {
            String text = mResultArea.getText();
            if (!text.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(text), null);
            }
        });
        panel.add(copyBtn);

        // 清空按钮
        JButton clearBtn = new JButton(L.get("generator_clear"));
        clearBtn.addActionListener(e -> mResultArea.setText(""));
        panel.add(clearBtn);

        return panel;
    }


    /**
     * 生成数据
     */
    private void generateData() {
        int count = (Integer) mCountSpinner.getValue();
        List<String> allResults = new ArrayList<>();

        // 获取配置参数
        String areaCode = null;
        if (mAreaCombo.getSelectedIndex() > 0) {
            String selected = (String) mAreaCombo.getSelectedItem();
            areaCode = selected.split("-")[0];
        }

        Integer gender = null;
        if (mGenderCombo.getSelectedIndex() == 1) {
            gender = 1;
        } else if (mGenderCombo.getSelectedIndex() == 2) {
            gender = 0;
        }

        String cardType = (String) mCardTypeCombo.getSelectedItem();

        String carrier = null;
        if (mCarrierCombo.getSelectedIndex() > 0) {
            carrier = (String) mCarrierCombo.getSelectedItem();
        }

        // 根据选中的复选框生成数据
        for (Map.Entry<String, JCheckBox> entry : mDataTypeCheckBoxes.entrySet()) {
            if (!entry.getValue().isSelected()) {
                continue;
            }

            String key = entry.getKey();
            String label = entry.getValue().getText();
            List<String> data = generateDataByType(key, count, areaCode, gender, cardType, carrier);

            if (!data.isEmpty()) {
                allResults.add("=== " + label + " ===");
                allResults.addAll(data);
                allResults.add("");
            }
        }

        if (allResults.isEmpty()) {
            mResultArea.setText(L.get("generator_no_type_selected"));
        } else {
            mResultArea.setText(String.join("\n", allResults));
        }
    }

    /**
     * 根据类型生成数据
     */
    private List<String> generateDataByType(String type, int count, String areaCode,
                                            Integer gender, String cardType, String carrier) {
        switch (type) {
            case "idcard":
                return DataGenerator.generateIdCard(areaCode, null, gender, count);
            case "bankcard":
                return DataGenerator.generateBankCard(cardType, count);
            case "phone":
                return DataGenerator.generatePhone(carrier, count);
            case "name":
                return DataGenerator.generateName(gender, count);
            case "creditcode":
                return DataGenerator.generateCreditCode(count);
            case "orgcode":
                return DataGenerator.generateOrgCode(count);
            case "taxpayerid":
                return DataGenerator.generateTaxpayerId(count);
            default:
                return new ArrayList<>();
        }
    }
}
