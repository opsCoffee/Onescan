package burp.vaycore.onescan.ui.widget;

import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Vector;

/**
 * 指纹列表
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpTable extends JTable {

    private final FpTable.FpTableModel mTableModel = new FpTable.FpTableModel();
    private final TableRowSorter<FpTable.FpTableModel> mTableRowSorter;

    public FpTable() {
        setModel(mTableModel);
        setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        mTableRowSorter = new TableRowSorter<>(mTableModel);
        setRowSorter(mTableRowSorter);
        getTableHeader().setReorderingAllowed(false);
        initColorLevelSorter();
        loadData();
        initColumnWidth();
    }

    public void loadData() {
        List<FpData> list = FpManager.getList();
        mTableModel.setData(list);
    }

    /**
     * 重新加载指纹数据
     */
    public void reloadData() {
        String path = FpManager.getPath();
        FpManager.init(path);
        List<FpData> list = FpManager.getList();
        mTableModel.setData(list);
    }

    /**
     * 初始化颜色等级排序
     */
    private void initColorLevelSorter() {
        // 颜色字段等级排序（固定最后一列为颜色等级）
        int comparatorColumn = getColumnNames().size() - 1;
        mTableRowSorter.setComparator(comparatorColumn, (Comparator<String>) (left, right) -> {
            int leftLevel = getColorLevel(left);
            int rightLevel = getColorLevel(right);
            return Integer.compare(leftLevel, rightLevel);
        });
    }

    /**
     * 初始化列宽
     */
    private void initColumnWidth() {
        int columnCount = getColumnModel().getColumnCount();
        for (int columnIndex = 0; columnIndex < columnCount; columnIndex++) {
            int columnWidth = calculateColumnWidth(columnIndex);
            this.getColumnModel().getColumn(columnIndex).setPreferredWidth(columnWidth);
        }
    }

    /**
     * 计算列的最佳宽度（根据内容自适应）
     *
     * @param columnIndex 列索引
     * @return 计算后的列宽
     */
    private int calculateColumnWidth(int columnIndex) {
        int columnCount = getColumnModel().getColumnCount();
        
        // ID 列、Enabled 列和 Color 列使用固定较小宽度
        if (columnIndex == 0 || columnIndex == 1 || columnIndex == columnCount - 1) {
            return 80;
        }
        
        // 获取列标题宽度
        String columnName = getColumnName(columnIndex);
        FontMetrics headerMetrics = getFontMetrics(getTableHeader().getFont());
        int headerWidth = headerMetrics.stringWidth(columnName);
        
        // 计算内容宽度（扫描所有行以确保宽度足够）
        int maxContentWidth = headerWidth;
        int rowCount = mTableModel.getRowCount();
        FontMetrics cellMetrics = getFontMetrics(getFont());
        
        for (int row = 0; row < rowCount; row++) {
            Object value = mTableModel.getValueAt(row, columnIndex);
            if (value != null) {
                String cellValue = value.toString();
                int cellWidth = cellMetrics.stringWidth(cellValue);
                maxContentWidth = Math.max(maxContentWidth, cellWidth);
            }
        }
        
        // 添加内边距（左右各15px，共30px）确保内容不会太挤
        int padding = 30;
        int calculatedWidth = maxContentWidth + padding;
        
        // 设置合理的最小宽度，避免列太窄
        int minWidth = 120;
        
        return Math.max(calculatedWidth, minWidth);
    }

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        JComponent component = (JComponent) super.prepareRenderer(renderer, row, column);
        if (component instanceof JLabel) {
            ((JLabel) component).setHorizontalAlignment(JLabel.LEFT);
        }
        return component;
    }

    /**
     * 设置过滤器
     *
     * @param filter 过滤器实例
     */
    public void setRowFilter(RowFilter<FpTable.FpTableModel, Integer> filter) {
        mTableRowSorter.setRowFilter(filter);
    }

    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public void addFpData(FpData data) {
        mTableModel.add(data);
        FpManager.addItem(data);
    }

    /**
     * 移除指纹数据
     *
     * @param rowIndex 指纹数据下标
     */
    public void removeFpData(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < mTableModel.getRowCount()) {
            mTableModel.remove(rowIndex);
            FpManager.removeItem(rowIndex);
        }
    }

    /**
     * 设置指纹数据
     *
     * @param rowIndex 指纹数据下标
     * @param data 指纹数据实例
     */
    public void setFpData(int rowIndex, FpData data) {
        if (rowIndex >= 0 && rowIndex < mTableModel.getRowCount()) {
            mTableModel.set(rowIndex, data);
            FpManager.setItem(rowIndex, data);
        }
    }

    /**
     * 获取指纹数据
     *
     * @param rowIndex 指纹数据下标
     * @return 失败返回null
     */
    public FpData getFpData(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < mTableModel.getRowCount()) {
            return mTableModel.mData.get(rowIndex);
        } else {
            return null;
        }
    }

    /**
     * 刷新所有字段
     */
    public void refreshColumns() {
        if (mTableModel == null) {
            return;
        }
        mTableModel.fireTableStructureChanged();
        initColorLevelSorter();
        initColumnWidth();
    }

    /**
     * 根据颜色名，获取颜色等级
     *
     * @param colorName 颜色名
     * @return 颜色等级
     */
    private static int getColorLevel(String colorName) {
        int level = FpManager.findColorLevelByName(colorName);
        return FpManager.sColorNames.length - level;
    }

    /**
     * 获取所有字段名
     *
     * @return 失败返回空列表
     */
    public static Vector<String> getColumnNames() {
        Vector<String> result = new Vector<>();
        // 首列添加默认的 ID 字段名
        result.add(L.get("fingerprint_table_columns.id"));
        // 启用状态列
        result.add(L.get("fingerprint_table_columns.enabled"));
        // 中间添加自定义字段名
        List<String> columnNames = FpManager.getColumnNames();
        result.addAll(columnNames);
        // 结尾添加默认的 Color 字段名
        result.add(L.get("fingerprint_table_columns.color"));
        return result;
    }

    public static class FpTableModel extends AbstractTableModel {

        private final ArrayList<FpData> mData = new ArrayList<>();

        public void add(FpData data) {
            if (data != null) {
                synchronized (mData) {
                    int id = getRowCount();
                    mData.add(data);
                    this.fireTableRowsInserted(id, id);
                }
            }
        }

        public void remove(int index) {
            synchronized (mData) {
                if (index >= 0 && index < getRowCount()) {
                    mData.remove(index);
                    this.fireTableRowsDeleted(index, index);
                }
            }
        }

        public void set(int index, FpData data) {
            if (data == null) {
                return;
            }
            synchronized (mData) {
                if (index >= 0 && index < getRowCount()) {
                    mData.set(index, data);
                    this.fireTableRowsUpdated(index, index);
                }
            }
        }

        public void setData(List<FpData> data) {
            if (data == null || data.isEmpty()) {
                return;
            }
            synchronized (mData) {
                mData.clear();
                if (!data.isEmpty()) {
                    mData.addAll(data);
                }
                this.fireTableDataChanged();
            }
        }

        public int getRowCount() {
            return mData.size();
        }

        public int getColumnCount() {
            return getColumnNames().size();
        }

        public String getColumnName(int column) {
            return getColumnNames().get(column);
        }

        public Object getValueAt(int rowIndex, int columnIndex) {
            String columnName = getColumnName(columnIndex);
            FpData data = mData.get(rowIndex);
            if (columnIndex == 0) {
                return rowIndex + 1;
            } else if (columnIndex == getColumnCount() - 1) {
                return data.getColor();
            }
            // 启用列为第2列
            if (columnIndex == 1) {
                return data.isEnabled();
            }
            // 根据字段名，获取指纹字段 ID 值
            String columnId = FpManager.findColumnIdByName(columnName);
            if (columnId == null) {
                return "";
            }
            // 通过指纹字段 ID 值，获取参数值
            ArrayList<FpData.Param> params = data.getParams();
            for (FpData.Param param : params) {
                if (param == null) {
                    continue;
                }
                if (columnId.equals(param.getK())) {
                    return param.getV();
                }
            }
            return "";
        }

        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) {
                return Integer.class;
            }
            if (columnIndex == 1) {
                return Boolean.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            // 仅允许编辑启用列
            return columnIndex == 1;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= getRowCount()) {
                return;
            }
            if (columnIndex != 1) {
                return;
            }
            boolean enabled;
            if (aValue instanceof Boolean) {
                enabled = (Boolean) aValue;
            } else if (aValue instanceof String) {
                enabled = Boolean.parseBoolean((String) aValue);
            } else {
                return;
            }
            FpData data = mData.get(rowIndex);
            if (data.isEnabled() == enabled) {
                return;
            }
            data.setEnabled(enabled);
            // 同步到配置
            FpManager.setItem(rowIndex, data);
            // 刷新单元格
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
