package burp.onescan.common;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 数据生成工具类
 * <p>
 * 提供身份证号、银行卡号、手机号、统一社会信用代码、姓名等测试数据的生成功能
 * <p>
 * Created by vaycore on 2024-12-11.
 */
public class DataGenerator {

    private static final Random sRandom = new Random();

    // ==================== 地区码数据 ====================
    private static final String[][] AREA_CODES = {
            {"110101", "北京市东城区"}, {"110102", "北京市西城区"}, {"110105", "北京市朝阳区"},
            {"310101", "上海市黄浦区"}, {"310104", "上海市徐汇区"}, {"310115", "上海市浦东新区"},
            {"440103", "广州市荔湾区"}, {"440104", "广州市越秀区"}, {"440106", "广州市天河区"},
            {"440303", "深圳市罗湖区"}, {"440304", "深圳市福田区"}, {"440305", "深圳市南山区"},
            {"330102", "杭州市上城区"}, {"330103", "杭州市下城区"}, {"330106", "杭州市西湖区"},
            {"320102", "南京市玄武区"}, {"320104", "南京市秦淮区"}, {"320105", "南京市建邺区"},
            {"510104", "成都市锦江区"}, {"510105", "成都市青羊区"}, {"510107", "成都市武侯区"},
            {"500103", "重庆市渝中区"}, {"500105", "重庆市江北区"}, {"500106", "重庆市沙坪坝区"},
            {"420102", "武汉市江岸区"}, {"420103", "武汉市江汉区"}, {"420104", "武汉市硚口区"},
            {"610102", "西安市新城区"}, {"610103", "西安市碑林区"}, {"610104", "西安市莲湖区"}
    };

    // ==================== 身份证校验码权重和映射 ====================
    private static final int[] ID_CARD_WEIGHTS = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    private static final char[] ID_CARD_CHECK_CODES = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};

    // ==================== 银行BIN码数据 ====================
    private static final String[][] BANK_BINS_DEBIT = {
            {"621226", "19", "工商银行"}, {"621700", "19", "建设银行"}, {"622848", "19", "农业银行"},
            {"621785", "19", "中国银行"}, {"621483", "16", "招商银行"}, {"622588", "19", "兴业银行"},
            {"621660", "16", "交通银行"}, {"622609", "16", "光大银行"}, {"622689", "16", "民生银行"},
            {"622155", "16", "华夏银行"}, {"622568", "16", "平安银行"}, {"621799", "16", "浦发银行"}
    };

    private static final String[][] BANK_BINS_CREDIT = {
            {"622230", "16", "工商银行"}, {"622280", "16", "建设银行"}, {"622836", "16", "农业银行"},
            {"625912", "16", "中国银行"}, {"622575", "16", "招商银行"}, {"622909", "16", "兴业银行"},
            {"622258", "16", "交通银行"}, {"622660", "16", "光大银行"}, {"622622", "16", "民生银行"},
            {"622636", "16", "华夏银行"}, {"622986", "16", "平安银行"}, {"622521", "16", "浦发银行"}
    };


    // ==================== 手机号段数据 ====================
    private static final String[][] PHONE_PREFIXES = {
            {"中国移动", "134,135,136,137,138,139,147,150,151,152,157,158,159,178,182,183,184,187,188,195,198"},
            {"中国联通", "130,131,132,145,155,156,166,175,176,185,186,196"},
            {"中国电信", "133,149,153,173,177,180,181,189,191,199"}
    };

    // ==================== 统一社会信用代码字符集和权重 ====================
    private static final String CREDIT_CODE_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY";
    private static final int[] CREDIT_CODE_WEIGHTS = {1, 3, 9, 27, 19, 26, 16, 17, 8, 24, 10, 30, 28, 22, 4, 12, 5};
    private static final String[] DEPT_CODES = {"1", "5", "9", "Y"};
    private static final String[] TYPE_CODES = {"1", "2", "3", "9"};

    // ==================== 姓名数据 ====================
    private static final String[] SURNAMES = {
            "王", "李", "张", "刘", "陈", "杨", "黄", "赵", "周", "吴",
            "徐", "孙", "马", "胡", "朱", "郭", "何", "罗", "高", "林",
            "郑", "梁", "谢", "宋", "唐", "许", "韩", "冯", "邓", "曹",
            "彭", "曾", "肖", "田", "董", "袁", "潘", "于", "蒋", "蔡",
            "余", "杜", "叶", "程", "苏", "魏", "吕", "丁", "任", "沈"
    };

    private static final String[] MALE_NAMES = {
            "伟", "强", "磊", "军", "勇", "杰", "涛", "明", "超", "华",
            "刚", "辉", "鹏", "俊", "峰", "浩", "宇", "轩", "博", "文",
            "志", "建", "国", "海", "飞", "龙", "威", "斌", "健", "亮",
            "成", "平", "东", "林", "波", "宁", "兵", "坤", "鑫", "毅"
    };

    private static final String[] FEMALE_NAMES = {
            "芳", "娟", "敏", "静", "丽", "艳", "红", "梅", "玲", "霞",
            "燕", "萍", "华", "英", "慧", "婷", "雪", "琳", "晶", "洁",
            "倩", "颖", "欣", "蕾", "薇", "莉", "娜", "琴", "露", "瑶",
            "雯", "璐", "怡", "悦", "媛", "萌", "菲", "茜", "蓉", "岚"
    };

    // ==================== 虚拟地址数据 ====================
    // 省市区详细数据：省份, 城市, 区县, 区号
    private static final String[][] PROVINCE_CITY_DISTRICT = {
            {"北京市", "北京市", "东城区", "010"}, {"北京市", "北京市", "西城区", "010"},
            {"北京市", "北京市", "朝阳区", "010"}, {"北京市", "北京市", "海淀区", "010"},
            {"上海市", "上海市", "黄浦区", "021"}, {"上海市", "上海市", "徐汇区", "021"},
            {"上海市", "上海市", "浦东新区", "021"}, {"上海市", "上海市", "静安区", "021"},
            {"广东省", "广州市", "天河区", "020"}, {"广东省", "广州市", "越秀区", "020"},
            {"广东省", "深圳市", "南山区", "0755"}, {"广东省", "深圳市", "福田区", "0755"},
            {"浙江省", "杭州市", "西湖区", "0571"}, {"浙江省", "杭州市", "上城区", "0571"},
            {"浙江省", "宁波市", "海曙区", "0574"}, {"浙江省", "宁波市", "鄞州区", "0574"},
            {"江苏省", "南京市", "玄武区", "025"}, {"江苏省", "南京市", "秦淮区", "025"},
            {"江苏省", "苏州市", "姑苏区", "0512"}, {"江苏省", "苏州市", "工业园区", "0512"},
            {"四川省", "成都市", "锦江区", "028"}, {"四川省", "成都市", "武侯区", "028"},
            {"湖北省", "武汉市", "武昌区", "027"}, {"湖北省", "武汉市", "江汉区", "027"},
            {"陕西省", "西安市", "雁塔区", "029"}, {"陕西省", "西安市", "碑林区", "029"},
            {"重庆市", "重庆市", "渝中区", "023"}, {"重庆市", "重庆市", "江北区", "023"},
            {"山东省", "济南市", "历下区", "0531"}, {"山东省", "青岛市", "市南区", "0532"},
            {"福建省", "福州市", "鼓楼区", "0591"}, {"福建省", "厦门市", "思明区", "0592"},
            {"湖南省", "长沙市", "岳麓区", "0731"}, {"湖南省", "长沙市", "芙蓉区", "0731"},
            {"河南省", "郑州市", "金水区", "0371"}, {"河南省", "郑州市", "中原区", "0371"},
            {"安徽省", "合肥市", "蜀山区", "0551"}, {"安徽省", "合肥市", "庐阳区", "0551"},
            {"辽宁省", "沈阳市", "和平区", "024"}, {"辽宁省", "大连市", "中山区", "0411"},
            {"云南省", "昆明市", "五华区", "0871"}, {"云南省", "昆明市", "盘龙区", "0871"},
            {"贵州省", "贵阳市", "南明区", "0851"}, {"贵州省", "贵阳市", "云岩区", "0851"},
            {"天津市", "天津市", "和平区", "022"}, {"天津市", "天津市", "南开区", "022"}
    };

    // 街道/镇名
    private static final String[] STREETS = {
            "人民路街道", "解放路街道", "建设路街道", "中山路街道", "和平路街道",
            "新华路街道", "朝阳路街道", "东风路街道", "文化路街道", "光明路街道",
            "幸福街道", "金融街街道", "科技园街道", "高新区街道", "经济开发区街道"
    };

    // 路名
    private static final String[] ROADS = {
            "人民路", "解放路", "建设路", "中山路", "和平路", "新华路", "朝阳路",
            "东风路", "文化路", "光明路", "长江路", "黄河路", "泰山路", "华山路",
            "青年路", "友谊路", "团结路", "胜利路", "前进路", "创业路"
    };

    // 小区名
    private static final String[] COMMUNITIES = {
            "阳光花园", "幸福家园", "和谐小区", "金色家园", "翠苑小区",
            "龙湖花园", "万科城", "绿地新都会", "保利花园", "碧桂园",
            "恒大名都", "融创城", "华润置地", "中海国际", "招商花园城",
            "世纪花园", "东方明珠", "紫荆花园", "桂花苑", "梅花小区"
    };

    // ==================== 企业信息数据 ====================
    // 公司名称前缀词
    private static final String[] COMPANY_PREFIXES = {
            "华", "中", "新", "国", "东", "南", "西", "北", "金", "银",
            "盛", "恒", "永", "鑫", "瑞", "嘉", "泰", "宏", "伟", "创"
    };

    // 公司名称中间词
    private static final String[] COMPANY_MIDDLES = {
            "达", "通", "联", "合", "信", "诚", "源", "丰", "茂", "盈",
            "辉", "腾", "飞", "翔", "龙", "凤", "祥", "福", "康", "安"
    };

    // 行业词
    private static final String[] INDUSTRIES = {
            "科技", "贸易", "投资", "建设", "电子", "网络", "信息", "软件",
            "商贸", "实业", "物流", "传媒", "文化", "教育", "咨询", "服务",
            "制造", "机械", "材料", "能源", "环保", "医药", "食品", "农业"
    };

    // 公司类型后缀
    private static final String[] COMPANY_TYPES = {
            "有限公司", "有限责任公司", "股份有限公司", "集团有限公司"
    };

    // 银行列表（用于开户行）
    private static final String[] BANKS = {
            "中国工商银行", "中国建设银行", "中国农业银行", "中国银行",
            "交通银行", "招商银行", "中信银行", "光大银行", "民生银行",
            "华夏银行", "平安银行", "浦发银行", "兴业银行", "广发银行"
    };

    // 支行名称后缀
    private static final String[] BRANCH_SUFFIXES = {
            "支行", "分行营业部", "支行营业室"
    };

    private DataGenerator() {
        // 工具类禁止实例化
    }

    // ==================== 身份证号生成 ====================

    /**
     * 生成随机身份证号
     *
     * @param count 生成数量
     * @return 身份证号列表
     */
    public static List<String> generateIdCard(int count) {
        return generateIdCard(null, null, null, count);
    }

    /**
     * 生成身份证号
     *
     * @param areaCode  地区码（6位），null表示随机
     * @param birthDate 出生日期，null表示随机（18-60岁）
     * @param gender    性别（0女1男），null表示随机
     * @param count     生成数量
     * @return 身份证号列表
     */
    public static List<String> generateIdCard(String areaCode, LocalDate birthDate, Integer gender, int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleIdCard(areaCode, birthDate, gender));
        }
        return result;
    }

    private static String generateSingleIdCard(String areaCode, LocalDate birthDate, Integer gender) {
        StringBuilder sb = new StringBuilder(18);
        // 地区码
        if (areaCode == null || areaCode.length() != 6) {
            areaCode = AREA_CODES[sRandom.nextInt(AREA_CODES.length)][0];
        }
        sb.append(areaCode);
        // 出生日期
        if (birthDate == null) {
            int age = 18 + sRandom.nextInt(43); // 18-60岁
            birthDate = LocalDate.now().minusYears(age).minusDays(sRandom.nextInt(365));
        }
        sb.append(String.format("%04d%02d%02d", birthDate.getYear(), birthDate.getMonthValue(), birthDate.getDayOfMonth()));
        // 顺序码（奇数男，偶数女）
        int seq = sRandom.nextInt(500) * 2;
        if (gender == null) {
            gender = sRandom.nextInt(2);
        }
        if (gender == 1) {
            seq += 1; // 男性为奇数
        }
        sb.append(String.format("%03d", seq));
        // 校验码
        sb.append(calculateIdCardCheckCode(sb.toString()));
        return sb.toString();
    }

    private static char calculateIdCardCheckCode(String idCard17) {
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            sum += (idCard17.charAt(i) - '0') * ID_CARD_WEIGHTS[i];
        }
        return ID_CARD_CHECK_CODES[sum % 11];
    }


    // ==================== 银行卡号生成 ====================

    /**
     * 生成随机银行卡号（借记卡）
     *
     * @param count 生成数量
     * @return 银行卡号列表（格式：卡号,银行名称(卡类型)）
     */
    public static List<String> generateBankCard(int count) {
        return generateBankCard("借记卡", count);
    }

    /**
     * 生成银行卡号
     *
     * @param cardType 卡类型（借记卡/信用卡）
     * @param count    生成数量
     * @return 银行卡号列表（格式：卡号,银行名称(卡类型)）
     */
    public static List<String> generateBankCard(String cardType, int count) {
        List<String> result = new ArrayList<>(count);
        String[][] bins = "信用卡".equals(cardType) ? BANK_BINS_CREDIT : BANK_BINS_DEBIT;
        String type = "信用卡".equals(cardType) ? "信用卡" : "借记卡";
        for (int i = 0; i < count; i++) {
            String[] binData = bins[sRandom.nextInt(bins.length)];
            String cardNo = generateSingleBankCard(binData[0], Integer.parseInt(binData[1]));
            result.add(cardNo + "," + binData[2] + "(" + type + ")");
        }
        return result;
    }

    private static String generateSingleBankCard(String bin, int length) {
        StringBuilder sb = new StringBuilder(length);
        sb.append(bin);
        // 生成中间位（除BIN和校验位外的位数）
        int middleLength = length - bin.length() - 1;
        for (int i = 0; i < middleLength; i++) {
            sb.append(sRandom.nextInt(10));
        }
        // 计算Luhn校验位
        sb.append(calculateLuhnCheckDigit(sb.toString()));
        return sb.toString();
    }

    private static int calculateLuhnCheckDigit(String cardNoWithoutCheck) {
        int sum = 0;
        boolean alternate = true;
        for (int i = cardNoWithoutCheck.length() - 1; i >= 0; i--) {
            int digit = cardNoWithoutCheck.charAt(i) - '0';
            if (alternate) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            alternate = !alternate;
        }
        return (10 - (sum % 10)) % 10;
    }

    // ==================== 手机号生成 ====================

    /**
     * 生成随机手机号
     *
     * @param count 生成数量
     * @return 手机号列表
     */
    public static List<String> generatePhone(int count) {
        return generatePhone(null, count);
    }

    /**
     * 生成手机号
     *
     * @param carrier 运营商（中国移动/中国联通/中国电信），null表示随机
     * @param count   生成数量
     * @return 手机号列表
     */
    public static List<String> generatePhone(String carrier, int count) {
        List<String> result = new ArrayList<>(count);
        String[] prefixes = getPhonePrefixes(carrier);
        for (int i = 0; i < count; i++) {
            String prefix = prefixes[sRandom.nextInt(prefixes.length)];
            StringBuilder sb = new StringBuilder(11);
            sb.append(prefix);
            for (int j = 0; j < 8; j++) {
                sb.append(sRandom.nextInt(10));
            }
            result.add(sb.toString());
        }
        return result;
    }

    private static String[] getPhonePrefixes(String carrier) {
        if (carrier == null) {
            // 合并所有运营商号段
            List<String> allPrefixes = new ArrayList<>();
            for (String[] data : PHONE_PREFIXES) {
                for (String prefix : data[1].split(",")) {
                    allPrefixes.add(prefix);
                }
            }
            return allPrefixes.toArray(new String[0]);
        }
        for (String[] data : PHONE_PREFIXES) {
            if (data[0].equals(carrier)) {
                return data[1].split(",");
            }
        }
        return getPhonePrefixes(null);
    }

    /**
     * 获取运营商列表
     *
     * @return 运营商名称数组
     */
    public static String[] getCarriers() {
        String[] carriers = new String[PHONE_PREFIXES.length];
        for (int i = 0; i < PHONE_PREFIXES.length; i++) {
            carriers[i] = PHONE_PREFIXES[i][0];
        }
        return carriers;
    }


    // ==================== 统一社会信用代码生成 ====================

    /**
     * 生成随机统一社会信用代码
     *
     * @param count 生成数量
     * @return 统一社会信用代码列表
     */
    public static List<String> generateCreditCode(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleCreditCode());
        }
        return result;
    }

    private static String generateSingleCreditCode() {
        StringBuilder sb = new StringBuilder(18);
        // 登记管理部门代码
        sb.append(DEPT_CODES[sRandom.nextInt(DEPT_CODES.length)]);
        // 机构类别代码
        sb.append(TYPE_CODES[sRandom.nextInt(TYPE_CODES.length)]);
        // 登记管理机关行政区划码（使用身份证地区码）
        sb.append(AREA_CODES[sRandom.nextInt(AREA_CODES.length)][0]);
        // 主体标识码（9位随机）
        for (int i = 0; i < 9; i++) {
            sb.append(CREDIT_CODE_CHARS.charAt(sRandom.nextInt(CREDIT_CODE_CHARS.length())));
        }
        // 校验码
        sb.append(calculateCreditCodeCheckChar(sb.toString()));
        return sb.toString();
    }

    private static char calculateCreditCodeCheckChar(String code17) {
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            int index = CREDIT_CODE_CHARS.indexOf(code17.charAt(i));
            sum += index * CREDIT_CODE_WEIGHTS[i];
        }
        int remainder = sum % 31;
        int checkIndex = (31 - remainder) % 31;
        return CREDIT_CODE_CHARS.charAt(checkIndex);
    }

    // ==================== 组织机构代码生成 ====================

    // 组织机构代码校验码权重
    private static final int[] ORG_CODE_WEIGHTS = {3, 7, 9, 10, 5, 8, 4, 2};

    /**
     * 生成随机组织机构代码（9位）
     *
     * @param count 生成数量
     * @return 组织机构代码列表
     */
    public static List<String> generateOrgCode(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleOrgCode());
        }
        return result;
    }

    private static String generateSingleOrgCode() {
        StringBuilder sb = new StringBuilder(9);
        // 生成8位随机数字
        for (int i = 0; i < 8; i++) {
            sb.append(sRandom.nextInt(10));
        }
        // 计算校验码
        int sum = 0;
        for (int i = 0; i < 8; i++) {
            sum += (sb.charAt(i) - '0') * ORG_CODE_WEIGHTS[i];
        }
        int c9 = 11 - (sum % 11);
        if (c9 == 11) {
            sb.append('0');
        } else if (c9 == 10) {
            sb.append('X');
        } else {
            sb.append(c9);
        }
        return sb.toString();
    }

    // ==================== 纳税人识别号生成 ====================

    /**
     * 生成随机纳税人识别号（15位）
     *
     * @param count 生成数量
     * @return 纳税人识别号列表
     */
    public static List<String> generateTaxpayerId(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleTaxpayerId());
        }
        return result;
    }

    private static String generateSingleTaxpayerId() {
        StringBuilder sb = new StringBuilder(15);
        // 6位行政区划码
        sb.append(AREA_CODES[sRandom.nextInt(AREA_CODES.length)][0]);
        // 9位组织机构代码
        sb.append(generateSingleOrgCode());
        return sb.toString();
    }

    // ==================== 姓名生成 ====================

    /**
     * 生成随机姓名
     *
     * @param count 生成数量
     * @return 姓名列表
     */
    public static List<String> generateName(int count) {
        return generateName(null, count);
    }

    /**
     * 生成姓名
     *
     * @param gender 性别（0女1男），null表示随机
     * @param count  生成数量
     * @return 姓名列表
     */
    public static List<String> generateName(Integer gender, int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleName(gender));
        }
        return result;
    }

    private static String generateSingleName(Integer gender) {
        StringBuilder sb = new StringBuilder();
        // 姓氏
        sb.append(SURNAMES[sRandom.nextInt(SURNAMES.length)]);
        // 名字（1-2个字）
        String[] names = (gender == null ? sRandom.nextInt(2) : gender) == 1 ? MALE_NAMES : FEMALE_NAMES;
        int nameLength = 1 + sRandom.nextInt(2);
        for (int i = 0; i < nameLength; i++) {
            sb.append(names[sRandom.nextInt(names.length)]);
        }
        return sb.toString();
    }

    // ==================== 辅助方法 ====================

    /**
     * 获取地区码列表
     *
     * @return 地区码数组（格式：地区码-地区名称）
     */
    public static String[] getAreaCodes() {
        String[] result = new String[AREA_CODES.length];
        for (int i = 0; i < AREA_CODES.length; i++) {
            result[i] = AREA_CODES[i][0] + "-" + AREA_CODES[i][1];
        }
        return result;
    }

    /**
     * 获取银行卡类型列表
     *
     * @return 卡类型数组
     */
    public static String[] getCardTypes() {
        return new String[]{"借记卡", "信用卡"};
    }

    /**
     * 获取性别列表
     *
     * @return 性别数组
     */
    public static String[] getGenders() {
        return new String[]{"随机", "男", "女"};
    }

    // ==================== 虚拟地址生成 ====================

    /**
     * 生成随机虚拟地址
     *
     * @param count 生成数量
     * @return 虚拟地址列表
     */
    public static List<String> generateAddress(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleAddress());
        }
        return result;
    }

    private static String generateSingleAddress() {
        StringBuilder sb = new StringBuilder();
        // 省市区
        String[] location = PROVINCE_CITY_DISTRICT[sRandom.nextInt(PROVINCE_CITY_DISTRICT.length)];
        sb.append(location[0]); // 省
        sb.append(location[1]); // 市
        sb.append(location[2]); // 区
        // 街道
        sb.append(STREETS[sRandom.nextInt(STREETS.length)]);
        // 路名
        sb.append(ROADS[sRandom.nextInt(ROADS.length)]);
        sb.append(sRandom.nextInt(200) + 1).append("号");
        // 小区
        sb.append(COMMUNITIES[sRandom.nextInt(COMMUNITIES.length)]);
        // 楼号
        sb.append(sRandom.nextInt(30) + 1).append("号楼");
        // 单元号（50%概率）
        if (sRandom.nextBoolean()) {
            sb.append(sRandom.nextInt(4) + 1).append("单元");
        }
        // 门牌号
        int floor = sRandom.nextInt(30) + 1;
        int room = sRandom.nextInt(4) + 1;
        sb.append(String.format("%d%02d", floor, room));
        return sb.toString();
    }

    // ==================== 企业信息生成 ====================

    /**
     * 生成随机企业名称
     *
     * @param count 生成数量
     * @return 企业名称列表
     */
    public static List<String> generateCompanyName(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleCompanyName());
        }
        return result;
    }

    private static String generateSingleCompanyName() {
        StringBuilder sb = new StringBuilder();
        // 地区名（从省市区数据中取城市名，去掉"市"字）
        String[] location = PROVINCE_CITY_DISTRICT[sRandom.nextInt(PROVINCE_CITY_DISTRICT.length)];
        String city = location[1].replace("市", "");
        sb.append(city);
        // 公司名称（前缀+中间词）
        sb.append(COMPANY_PREFIXES[sRandom.nextInt(COMPANY_PREFIXES.length)]);
        sb.append(COMPANY_MIDDLES[sRandom.nextInt(COMPANY_MIDDLES.length)]);
        // 行业
        sb.append(INDUSTRIES[sRandom.nextInt(INDUSTRIES.length)]);
        // 公司类型
        sb.append(COMPANY_TYPES[sRandom.nextInt(COMPANY_TYPES.length)]);
        return sb.toString();
    }

    /**
     * 生成随机开户行名称
     *
     * @param count 生成数量
     * @return 开户行名称列表
     */
    public static List<String> generateBankBranch(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleBankBranch());
        }
        return result;
    }

    private static String generateSingleBankBranch() {
        StringBuilder sb = new StringBuilder();
        // 银行名称
        sb.append(BANKS[sRandom.nextInt(BANKS.length)]);
        // 地区名（城市+区）
        String[] location = PROVINCE_CITY_DISTRICT[sRandom.nextInt(PROVINCE_CITY_DISTRICT.length)];
        sb.append(location[1].replace("市", ""));
        sb.append(location[2].replace("区", "").replace("县", ""));
        // 支行后缀
        sb.append(BRANCH_SUFFIXES[sRandom.nextInt(BRANCH_SUFFIXES.length)]);
        return sb.toString();
    }

    /**
     * 生成随机开户行帐号（对公账户）
     *
     * @param count 生成数量
     * @return 开户行帐号列表（格式：帐号,银行名称）
     */
    public static List<String> generateBankAccount(int count) {
        // 对公账户使用借记卡格式
        return generateBankCard("借记卡", count);
    }

    /**
     * 生成随机开户行电话
     *
     * @param count 生成数量
     * @return 开户行电话列表
     */
    public static List<String> generateBankPhone(int count) {
        List<String> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(generateSingleBankPhone());
        }
        return result;
    }

    private static String generateSingleBankPhone() {
        StringBuilder sb = new StringBuilder();
        // 区号
        String[] location = PROVINCE_CITY_DISTRICT[sRandom.nextInt(PROVINCE_CITY_DISTRICT.length)];
        sb.append(location[3]);
        sb.append("-");
        // 8位电话号码（首位不为0）
        sb.append(sRandom.nextInt(8) + 2); // 2-9
        for (int i = 0; i < 7; i++) {
            sb.append(sRandom.nextInt(10));
        }
        return sb.toString();
    }
}
