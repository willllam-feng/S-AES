import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/**
 * S-AES 加解密工具
 */
public class SAESGUI extends JFrame {
    // 全局组件配置
    private final JTabbedPane tabbedPane;
    private final Font baseFont = new Font("微软雅黑", Font.PLAIN, 12);
    private final int inputWidth = 450;
    private final int textAreaRows = 9;
    private final int textAreaCols = 80;
    private final Dimension inputMinSize = new Dimension(inputWidth, 28);
    private final Dimension scrollMinSize = new Dimension(750, 220);

    public SAESGUI() {
        // 窗口初始化
        setTitle("S-AES 加解密工具");
        setSize(950, 620);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(true);

        // 选项卡容器
        tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setFont(baseFont);
        tabbedPane.addTab("1. 基础加解密（16位）", createBasicTab());
        tabbedPane.addTab("2. ASCII字符串加解密", createASCIITab());
        tabbedPane.addTab("3. 双重加密（含中间相遇攻击）", createDoubleTab());
        tabbedPane.addTab("4. 三重加密", createTripleTab());
        tabbedPane.addTab("5. CBC模式（含篡改测试）", createCBCTab());

        add(tabbedPane);
    }

    /**
     * 通用GridBagConstraints配置
     */
    private GridBagConstraints getGBC() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 15, 8, 15);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        return gbc;
    }

    /**
     * 通用结果文本域创建
     */
    private JScrollPane createResultPanel() {
        JTextArea textArea = new JTextArea(textAreaRows, textAreaCols);
        textArea.setFont(baseFont);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(false);
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setMinimumSize(scrollMinSize);
        scrollPane.setPreferredSize(scrollMinSize);
        return scrollPane;
    }

    /**
     * 通用输入框创建
     */
    private JTextField createInputField() {
        JTextField field = new JTextField(inputWidth);
        field.setFont(baseFont);
        field.setMinimumSize(inputMinSize);
        field.setPreferredSize(inputMinSize);
        return field;
    }

    // -------------------------- 第1关：基础加解密选项卡 --------------------------
    private JPanel createBasicTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = getGBC();

        // 组件初始化
        JLabel plainLabel = new JLabel("明文（16位，4个十六进制字符，如0000）：");
        JTextField plainField = createInputField();
        JLabel keyLabel = new JLabel("密钥（16位，4个十六进制字符，如2D55）：");
        JTextField keyField = createInputField();

        JButton encryptBtn = new JButton("执行加密");
        JButton decryptBtn = new JButton("执行解密");
        JPanel btnPanel = new JPanel();
        btnPanel.add(encryptBtn);
        btnPanel.add(Box.createHorizontalStrut(20));
        btnPanel.add(decryptBtn);

        JLabel resultLabel = new JLabel("操作结果：");
        JScrollPane resultScroll = createResultPanel();
        JTextArea resultArea = (JTextArea) resultScroll.getViewport().getView();

        // 布局组装
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(plainLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(plainField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(keyField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
        panel.add(btnPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        panel.add(resultLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(resultScroll, gbc);

        // 加密按钮事件
        encryptBtn.addActionListener(e -> {
            try {
                String plainHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (plainHex.length() != 4) throw new IllegalArgumentException("明文必须为4个十六进制字符");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符");

                byte[] plain = SAESCore.hexToBytes(plainHex);
                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] cipher = SAESCore.encrypt16(plain, key);

                resultArea.setText("=== 基础加密成功 ===\n" +
                        "1. 输入明文（16位，十六进制）：" + plainHex + "\n" +
                        "2. 输入密钥（16位，十六进制）：" + keyHex + "\n" +
                        "3. 加密后密文（16位，十六进制）：" + SAESCore.bytesToHex(cipher) + "\n" +
                        "4. 交叉测试提示：其他组使用相同密钥加密该明文，应得到相同密文");
            } catch (Exception ex) {
                resultArea.setText("=== 基础加密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：\n" +
                        "- 十六进制字符仅支持0-9、A-F（不区分大小写）\n" +
                        "- 确保明文/密钥长度严格为4个字符（对应16位）");
            }
        });

        // 解密按钮事件
        decryptBtn.addActionListener(e -> {
            try {
                String cipherHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (cipherHex.length() != 4) throw new IllegalArgumentException("密文必须为4个十六进制字符（对应16位）");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符（对应16位）");

                byte[] cipher = SAESCore.hexToBytes(cipherHex);
                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] plain = SAESCore.decrypt16(cipher, key);

                resultArea.setText("=== 基础解密成功 ===\n" +
                        "1. 输入密文（16位，十六进制）：" + cipherHex + "\n" +
                        "2. 输入密钥（16位，十六进制）：" + keyHex + "\n" +
                        "3. 解密后明文（16位，十六进制）：" + SAESCore.bytesToHex(plain) + "\n" +
                        "4. 明文ASCII预览：" + new String(plain, StandardCharsets.US_ASCII) + "\n" +
                        "5. 交叉测试提示：接收其他组密文，用该密钥解密应得到原始明文");
            } catch (Exception ex) {
                resultArea.setText("=== 基础解密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：\n" +
                        "- 确认密文/密钥格式正确（4个十六进制字符）\n" +
                        "- 确保解密密钥与加密密钥完全一致");
            }
        });

        return panel;
    }

    // -------------------------- 第3关：ASCII字符串加解密选项卡 --------------------------
    private JPanel createASCIITab() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = getGBC();

        // 组件初始化
        JLabel strLabel = new JLabel("ASCII字符串（如HelloS-AES，支持任意可显字符）：");
        JTextField strField = createInputField();
        JLabel keyLabel = new JLabel("密钥（16位，4个十六进制字符，如2D55）：");
        JTextField keyField = createInputField();

        JButton encryptBtn = new JButton("字符串加密");
        JButton decryptBtn = new JButton("字符串解密");
        JPanel btnPanel = new JPanel();
        btnPanel.add(encryptBtn);
        btnPanel.add(Box.createHorizontalStrut(20));
        btnPanel.add(decryptBtn);

        JLabel resultLabel = new JLabel("操作结果：");
        JScrollPane resultScroll = createResultPanel();
        JTextArea resultArea = (JTextArea) resultScroll.getViewport().getView();

        // 布局组装
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(strLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(strField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(keyField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
        panel.add(btnPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        panel.add(resultLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(resultScroll, gbc);

        // 加密按钮事件
        encryptBtn.addActionListener(e -> {
            try {
                String plainStr = strField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (plainStr.isEmpty()) throw new IllegalArgumentException("请输入ASCII字符串（如Hello、Test123）");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符（对应16位）");

                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] cipherBytes = SAESCore.encryptASCII(plainStr, key);

                resultArea.setText("=== ASCII字符串加密成功 ===\n" +
                        "1. 原始ASCII字符串：" + plainStr + "\n" +
                        "2. 使用密钥（16位，十六进制）：" + keyHex + "\n" +
                        "3. 加密处理说明：\n" +
                        "   - 字符串转ASCII字节：" + Arrays.toString(plainStr.getBytes(StandardCharsets.US_ASCII)) + "\n" +
                        "   - 2字节分组补0：长度" + plainStr.length() + "→" + cipherBytes.length + "字节\n" +
                        "4. 密文（十六进制，建议传输格式）：" + SAESCore.bytesToHex(cipherBytes) + "\n" +
                        "5. 注意：密文为不可显乱码，需以十六进制保存/传输");
            } catch (Exception ex) {
                resultArea.setText("=== ASCII字符串加密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：确保密钥为4个十六进制字符，字符串不含非ASCII字符（如中文）");
            }
        });

        // 解密按钮事件
        decryptBtn.addActionListener(e -> {
            try {
                String cipherHex = strField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (cipherHex.isEmpty()) throw new IllegalArgumentException("请输入密文的十六进制字符串（如BC E9 1A）");
                if (cipherHex.length() % 2 != 0) throw new IllegalArgumentException("密文十六进制长度必须为偶数");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符（对应16位）");

                byte[] cipher = SAESCore.hexToBytes(cipherHex);
                byte[] key = SAESCore.hexToBytes(keyHex);
                String plainStr = SAESCore.decryptASCII(cipher, key);

                resultArea.setText("=== ASCII字符串解密成功 ===\n" +
                        "1. 输入密文（十六进制）：" + cipherHex + "\n" +
                        "2. 使用密钥（16位，十六进制）：" + keyHex + "\n" +
                        "3. 解密处理说明：\n" +
                        "   - 密文字节数：" + cipher.length + "字节（2字节分组解密）\n" +
                        "   - 自动去除末尾补0：原始" + cipher.length + "→" + plainStr.length() + "字符\n" +
                        "4. 解密后ASCII字符串：" + plainStr);
            } catch (Exception ex) {
                resultArea.setText("=== ASCII字符串解密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：\n" +
                        "- 密文十六进制需为偶数长度，且不含空格\n" +
                        "- 确保解密密钥与加密密钥完全一致");
            }
        });

        return panel;
    }

    // -------------------------- 第4关：双重加密选项卡 --------------------------
    private JPanel createDoubleTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = getGBC();

        // 组件初始化
        JLabel plainLabel = new JLabel("明文（16位，4个十六进制字符，如0000）：");
        JTextField plainField = createInputField();
        JLabel keyLabel = new JLabel("32位密钥（8个十六进制字符，如2D55AABB）：");
        JTextField keyField = createInputField();

        JButton encryptBtn = new JButton("双重加密");
        JButton decryptBtn = new JButton("双重解密");
        JPanel basicBtnPanel = new JPanel();
        basicBtnPanel.add(encryptBtn);
        basicBtnPanel.add(Box.createHorizontalStrut(20));
        basicBtnPanel.add(decryptBtn);

        JLabel mitmTitle = new JLabel("=== 中间相遇攻击（破解双重加密密钥） ===");
        mitmTitle.setFont(new Font("微软雅黑", Font.BOLD, 12));
        JLabel mitmPlainLabel = new JLabel("攻击明文（16位，4个十六进制字符）：");
        JTextField mitmPlainField = createInputField();
        JLabel mitmCipherLabel = new JLabel("攻击密文（16位，双重加密结果）：");
        JTextField mitmCipherField = createInputField();
        JButton mitmBtn = new JButton("执行攻击（约1-2秒）");
        mitmBtn.setFont(baseFont);

        JLabel resultLabel = new JLabel("操作结果：");
        JScrollPane resultScroll = createResultPanel();
        JTextArea resultArea = (JTextArea) resultScroll.getViewport().getView();

        // 布局组装
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(plainLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(plainField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(keyField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
        panel.add(basicBtnPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        panel.add(mitmTitle, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1;
        panel.add(mitmPlainLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 4; gbc.gridwidth = 2;
        panel.add(mitmPlainField, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        panel.add(mitmCipherLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2;
        panel.add(mitmCipherField, gbc);

        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 3;
        panel.add(mitmBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 1;
        panel.add(resultLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 7; gbc.gridwidth = 2;
        panel.add(resultScroll, gbc);

        // 双重加密按钮事件
        encryptBtn.addActionListener(e -> {
            try {
                String plainHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (plainHex.length() != 4) throw new IllegalArgumentException("明文必须为4个十六进制字符（对应16位）");
                if (keyHex.length() != 8) throw new IllegalArgumentException("32位密钥必须为8个十六进制字符（如2D55AABB）");

                byte[] plain = SAESCore.hexToBytes(plainHex);
                byte[] key32 = SAESCore.hexToBytes(keyHex);
                byte[] cipher = SAESCore.encryptDouble(plain, key32);

                String k1Hex = keyHex.substring(0, 4);
                String k2Hex = keyHex.substring(4, 8);
                resultArea.setText("=== 双重加密成功 ===\n" +
                        "1. 加密流程：明文 → K1加密 → K2加密 → 密文\n" +
                        "2. 输入明文（16位，十六进制）：" + plainHex + "\n" +
                        "3. 32位密钥拆分：\n" +
                        "   - K1（前16位）：" + k1Hex + "\n" +
                        "   - K2（后16位）：" + k2Hex + "\n" +
                        "4. 双重加密后密文（16位，十六进制）：" + SAESCore.bytesToHex(cipher));
            } catch (Exception ex) {
                resultArea.setText("=== 双重加密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：确保密钥为8个十六进制字符（对应32位K1+K2）");
            }
        });

        // 双重解密按钮事件
        decryptBtn.addActionListener(e -> {
            try {
                String cipherHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (cipherHex.length() != 4) throw new IllegalArgumentException("密文必须为4个十六进制字符（对应16位）");
                if (keyHex.length() != 8) throw new IllegalArgumentException("32位密钥必须为8个十六进制字符（如2D55AABB）");

                byte[] cipher = SAESCore.hexToBytes(cipherHex);
                byte[] key32 = SAESCore.hexToBytes(keyHex);
                byte[] plain = SAESCore.decryptDouble(cipher, key32);

                String k1Hex = keyHex.substring(0, 4);
                String k2Hex = keyHex.substring(4, 8);
                resultArea.setText("=== 双重解密成功 ===\n" +
                        "1. 解密流程：密文 → K2解密 → K1解密 → 明文\n" +
                        "2. 输入密文（16位，十六进制）：" + cipherHex + "\n" +
                        "3. 32位密钥拆分：\n" +
                        "   - K1（前16位）：" + k1Hex + "\n" +
                        "   - K2（后16位）：" + k2Hex + "\n" +
                        "4. 双重解密后明文（16位，十六进制）：" + SAESCore.bytesToHex(plain));
            } catch (Exception ex) {
                resultArea.setText("=== 双重解密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：确保密钥与加密时的K1+K2完全一致");
            }
        });

        // 中间相遇攻击按钮事件
        mitmBtn.addActionListener(e -> {
            try {
                String mitmPlainHex = mitmPlainField.getText().trim();
                String mitmCipherHex = mitmCipherField.getText().trim();
                if (mitmPlainHex.length() != 4 || mitmCipherHex.length() != 4) {
                    throw new IllegalArgumentException("明密文对必须均为4个十六进制字符（对应16位）");
                }

                resultArea.setText("=== 中间相遇攻击中 ===\n" +
                        "1. 攻击参数：\n" +
                        "   - 明文P：" + mitmPlainHex + "\n" +
                        "   - 双重加密密文C：" + mitmCipherHex + "\n" +
                        "2. 攻击进度：正在预计算K1加密结果（共65536种）...\n" +
                        "   （预计1-2秒，请勿关闭窗口）");

                // 线程安全包装变量
                final AtomicReference<String> keyHexRef = new AtomicReference<>("未找到有效密钥");
                final AtomicReference<Boolean> isKeyValidRef = new AtomicReference<>(false);
                final AtomicReference<byte[]> key32Ref = new AtomicReference<>(null);
                final AtomicReference<byte[]> mitmPlainRef = new AtomicReference<>(SAESCore.hexToBytes(mitmPlainHex));
                final AtomicReference<byte[]> mitmCipherRef = new AtomicReference<>(SAESCore.hexToBytes(mitmCipherHex));

                new Thread(() -> {
                    try {
                        byte[] threadMitmPlain = mitmPlainRef.get();
                        byte[] threadMitmCipher = mitmCipherRef.get();
                        byte[] threadKey32 = SAESCore.meetInTheMiddle(threadMitmPlain, threadMitmCipher);
                        key32Ref.set(threadKey32);

                        if (threadKey32 != null) {
                            String threadKeyHex = SAESCore.bytesToHex(threadKey32);
                            keyHexRef.set(threadKeyHex);
                            byte[] verifyCipher = SAESCore.encryptDouble(threadMitmPlain, threadKey32);
                            isKeyValidRef.set(Arrays.equals(verifyCipher, threadMitmCipher));
                        }

                        SwingUtilities.invokeLater(() -> {
                            byte[] uiKey32 = key32Ref.get();
                            String uiKeyHex = keyHexRef.get();
                            boolean uiIsKeyValid = isKeyValidRef.get();
                            byte[] uiMitmPlain = mitmPlainRef.get();

                            if (uiKey32 != null && uiIsKeyValid) {
                                String k1Hex = uiKeyHex.substring(0, 4);
                                String k2Hex = uiKeyHex.substring(4, 8);
                                resultArea.setText("=== 中间相遇攻击成功 ===\n" +
                                        "1. 攻击结果：\n" +
                                        "   - 破解的32位密钥（K1+K2）：" + uiKeyHex + "\n" +
                                        "   - K1（前16位）：" + k1Hex + "\n" +
                                        "   - K2（后16位）：" + k2Hex + "\n" +
                                        "2. 密钥验证：\n" +
                                        "   - 用K1+K2加密P：" + SAESCore.bytesToHex(SAESCore.encryptDouble(uiMitmPlain, uiKey32)) + "\n" +
                                        "   - 目标密文C：" + mitmCipherHex + "\n" +
                                        "   - 验证结果：一致（密钥正确）\n" +
                                        "3. 攻击原理：预计算所有K1的E(P,K1)→哈希表，遍历所有K2的D(C,K2)→匹配中间值（时间换空间）");
                            } else {
                                resultArea.setText("=== 中间相遇攻击失败 ===\n" +
                                        "1. 攻击参数：\n" +
                                        "   - 明文P：" + mitmPlainHex + "\n" +
                                        "   - 密文C：" + mitmCipherHex + "\n" +
                                        "2. 失败原因：未找到匹配的32位密钥\n" +
                                        "   排查建议：\n" +
                                        "   - 确认C是P通过S-AES双重加密的结果（非单次加密/其他算法）\n" +
                                        "   - 检查明密文对格式（均为4个十六进制字符，无空格/错误字符）");
                            }
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            resultArea.setText("=== 中间相遇攻击异常 ===\n" +
                                    "错误原因：" + ex.getMessage() + "\n" +
                                    "排查建议：确保SAESCore类的meetInTheMiddle方法正常调用（参数为16位字节数组）");
                        });
                    }
                }).start();
            } catch (Exception ex) {
                resultArea.setText("=== 中间相遇攻击参数错误 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "参数要求：\n" +
                        "   - 明文P：16位（4个十六进制字符，如0000、2D55）\n" +
                        "   - 密文C：16位（双重加密结果，4个十六进制字符）");
            }
        });

        return panel;
    }

    // -------------------------- 第4关：三重加密选项卡 --------------------------
    private JPanel createTripleTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = getGBC();

        // 组件初始化
        JLabel plainLabel = new JLabel("明文（16位，4个十六进制字符，如0000）：");
        JTextField plainField = createInputField();
        JLabel modeLabel = new JLabel("三重加密模式（二选一）：");
        JComboBox<String> modeCombo = new JComboBox<>(new String[]{
                "模式1（32位密钥K1+K2，流程：K1→K2→K1）",
                "模式2（48位密钥K1+K2+K3，流程：K1→K2→K3）"
        });
        modeCombo.setFont(baseFont);
        modeCombo.setMinimumSize(new Dimension(inputWidth, 28));
        modeCombo.setPreferredSize(new Dimension(inputWidth, 28));

        JLabel keyLabel = new JLabel("密钥（模式1=8字符；模式2=12字符）：");
        JTextField keyField = createInputField();
        JButton encryptBtn = new JButton("三重加密");
        JButton decryptBtn = new JButton("三重解密");
        JPanel btnPanel = new JPanel();
        btnPanel.add(encryptBtn);
        btnPanel.add(Box.createHorizontalStrut(20));
        btnPanel.add(decryptBtn);

        JLabel resultLabel = new JLabel("操作结果：");
        JScrollPane resultScroll = createResultPanel();
        JTextArea resultArea = (JTextArea) resultScroll.getViewport().getView();

        // 布局组装
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(plainLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(plainField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(modeLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(modeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
        panel.add(keyField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        panel.add(btnPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1;
        panel.add(resultLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 4; gbc.gridwidth = 2;
        panel.add(resultScroll, gbc);

        // 模式选择监听
        modeCombo.addActionListener(e -> {
            String selectedMode = (String) modeCombo.getSelectedItem();
            if (selectedMode.contains("模式1")) {
                keyLabel.setText("密钥（模式1=8个十六进制字符，如2D55AABB）：");
            } else {
                keyLabel.setText("密钥（模式2=12个十六进制字符，如2D55AABBCCDD）：");
            }
        });

        // 三重加密按钮事件
        encryptBtn.addActionListener(e -> {
            try {
                String plainHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                String selectedMode = (String) modeCombo.getSelectedItem();
                byte[] plain = SAESCore.hexToBytes(plainHex);
                byte[] cipher;
                String keyDesc = "";

                if (selectedMode.contains("模式1")) {
                    if (keyHex.length() != 8) throw new IllegalArgumentException("模式1需8个十六进制字符（32位K1+K2）");
                    byte[] key32 = SAESCore.hexToBytes(keyHex);
                    cipher = SAESCore.encryptTripleMode1(plain, key32);
                    keyDesc = "   - K1（前16位）：" + keyHex.substring(0, 4) + "\n" +
                              "   - K2（后16位）：" + keyHex.substring(4, 8) + "\n" +
                              "   - 加密流程：K1→K2→K1";
                } else {
                    if (keyHex.length() != 12) throw new IllegalArgumentException("模式2需12个十六进制字符（48位K1+K2+K3）");
                    byte[] key48 = SAESCore.hexToBytes(keyHex);
                    cipher = SAESCore.encryptTripleMode2(plain, key48);
                    keyDesc = "   - K1（前16位）：" + keyHex.substring(0, 4) + "\n" +
                              "   - K2（中16位）：" + keyHex.substring(4, 8) + "\n" +
                              "   - K3（后16位）：" + keyHex.substring(8, 12) + "\n" +
                              "   - 加密流程：K1→K2→K3";
                }

                resultArea.setText("=== 三重加密成功 ===\n" +
                        "1. 选择模式：" + selectedMode + "\n" +
                        "2. 输入明文（16位，十六进制）：" + plainHex + "\n" +
                        "3. 密钥信息：\n" + keyDesc + "\n" +
                        "4. 三重加密后密文（16位，十六进制）：" + SAESCore.bytesToHex(cipher));
            } catch (Exception ex) {
                resultArea.setText("=== 三重加密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：根据所选模式确认密钥长度（模式1=8字符，模式2=12字符）");
            }
        });

        // 三重解密按钮事件
        decryptBtn.addActionListener(e -> {
            try {
                String cipherHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                String selectedMode = (String) modeCombo.getSelectedItem();
                byte[] cipher = SAESCore.hexToBytes(cipherHex);
                byte[] plain;
                String keyDesc = "";

                if (selectedMode.contains("模式1")) {
                    if (keyHex.length() != 8) throw new IllegalArgumentException("模式1需8个十六进制字符（32位K1+K2）");
                    byte[] key32 = SAESCore.hexToBytes(keyHex);
                    plain = SAESCore.decryptTripleMode1(cipher, key32);
                    keyDesc = "   - K1（前16位）：" + keyHex.substring(0, 4) + "\n" +
                              "   - K2（后16位）：" + keyHex.substring(4, 8) + "\n" +
                              "   - 解密流程：K1→K2→K1";
                } else {
                    if (keyHex.length() != 12) throw new IllegalArgumentException("模式2需12个十六进制字符（48位K1+K2+K3）");
                    byte[] key48 = SAESCore.hexToBytes(keyHex);
                    plain = SAESCore.decryptTripleMode2(cipher, key48);
                    keyDesc = "   - K1（前16位）：" + keyHex.substring(0, 4) + "\n" +
                              "   - K2（中16位）：" + keyHex.substring(4, 8) + "\n" +
                              "   - K3（后16位）：" + keyHex.substring(8, 12) + "\n" +
                              "   - 解密流程：K3→K2→K1";
                }

                resultArea.setText("=== 三重解密成功 ===\n" +
                        "1. 选择模式：" + selectedMode + "\n" +
                        "2. 输入密文（16位，十六进制）：" + cipherHex + "\n" +
                        "3. 密钥信息：\n" + keyDesc + "\n" +
                        "4. 三重解密后明文（16位，十六进制）：" + SAESCore.bytesToHex(plain));
            } catch (Exception ex) {
                resultArea.setText("=== 三重解密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：确保密钥与加密模式、密钥完全一致");
            }
        });

        return panel;
    }

    // -------------------------- 第5关：CBC模式选项卡 --------------------------
    private JPanel createCBCTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = getGBC();

        // 组件初始化
        JLabel plainLabel = new JLabel("明文（任意ASCII字符串，如CBC Mode Test）：");
        JTextField plainField = createInputField();
        plainField.setText("CBC Mode Test With Long Text");
        JLabel keyLabel = new JLabel("密钥（16位，4个十六进制字符，如2D55）：");
        JTextField keyField = createInputField();
        keyField.setText("2D55");
        JLabel ivLabel = new JLabel("初始向量IV（16位，4个十六进制字符，如1234）：");
        JTextField ivField = createInputField();
        ivField.setText("1234");

        JButton encryptBtn = new JButton("CBC加密");
        JButton decryptBtn = new JButton("CBC解密");
        JButton tamperBtn = new JButton("执行密文篡改测试");
        JPanel btnPanel = new JPanel();
        btnPanel.add(encryptBtn);
        btnPanel.add(Box.createHorizontalStrut(20));
        btnPanel.add(decryptBtn);

        JLabel resultLabel = new JLabel("操作结果：");
        JScrollPane resultScroll = createResultPanel();
        JTextArea resultArea = (JTextArea) resultScroll.getViewport().getView();

        // 布局组装
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(plainLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(plainField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(keyField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(ivLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
        panel.add(ivField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        panel.add(btnPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        panel.add(tamperBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        panel.add(resultLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2;
        panel.add(resultScroll, gbc);

        // CBC加密按钮事件
        encryptBtn.addActionListener(e -> {
            try {
                String plainStr = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                String ivHex = ivField.getText().trim();
                if (plainStr.isEmpty()) throw new IllegalArgumentException("请输入明文（如CBC Mode Test）");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符（16位）");
                if (ivHex.length() != 4) throw new IllegalArgumentException("IV必须为4个十六进制字符（16位）");

                byte[] plain = plainStr.getBytes(StandardCharsets.US_ASCII);
                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] iv = SAESCore.hexToBytes(ivHex);
                byte[] cipher = SAESCore.encryptCBC(plain, key, iv);

                resultArea.setText("=== CBC模式加密成功 ===\n" +
                        "1. CBC加密流程：C0=IV，Ci=E(Pi XOR Ci-1, K)\n" +
                        "2. 输入参数：\n" +
                        "   - 明文（ASCII）：" + plainStr + "\n" +
                        "   - 密钥（16位，十六进制）：" + keyHex + "\n" +
                        "   - 初始向量IV（16位，十六进制）：" + ivHex + "\n" +
                        "3. 加密结果：\n" +
                        "   - 明文字节数：" + plain.length + "→补0后" + (plain.length + (2 - plain.length%2)%2) + "字节\n" +
                        "   - 密文（含IV，十六进制）：" + SAESCore.bytesToHex(cipher) + "\n" +
                        "   - 密文结构：前2字节=IV，后续=加密分组");
            } catch (Exception ex) {
                resultArea.setText("=== CBC模式加密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：IV和密钥均需为4个十六进制字符，明文不含非ASCII字符");
            }
        });

        // CBC解密按钮事件
        decryptBtn.addActionListener(e -> {
            try {
                String cipherHex = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                if (cipherHex.isEmpty()) throw new IllegalArgumentException("请输入CBC密文（含IV，十六进制）");
                if (cipherHex.length() < 4) throw new IllegalArgumentException("密文（含IV）至少需4个十六进制字符（IV占2字节）");
                if (cipherHex.length() % 2 != 0) throw new IllegalArgumentException("密文十六进制长度必须为偶数");
                if (keyHex.length() != 4) throw new IllegalArgumentException("密钥必须为4个十六进制字符（16位）");

                byte[] cipher = SAESCore.hexToBytes(cipherHex);
                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] plain = SAESCore.decryptCBC(cipher, key);
                String plainStr = new String(plain, StandardCharsets.US_ASCII);
                byte[] iv = Arrays.copyOfRange(cipher, 0, 2);

                resultArea.setText("=== CBC模式解密成功 ===\n" +
                        "1. CBC解密流程：Pi=D(Ci, K) XOR Ci-1（C0=IV）\n" +
                        "2. 输入参数：\n" +
                        "   - 密文（含IV，十六进制）：" + cipherHex + "\n" +
                        "   - 密钥（16位，十六进制）：" + keyHex + "\n" +
                        "3. 解密结果：\n" +
                        "   - 从密文提取IV（16位，十六进制）：" + SAESCore.bytesToHex(iv) + "\n" +
                        "   - 解密后明文（ASCII）：" + plainStr + "\n" +
                        "   - 明文字节数：" + plain.length + "（自动去除补0）");
            } catch (Exception ex) {
                resultArea.setText("=== CBC模式解密失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "排查建议：\n" +
                        "- 密文需包含IV（前2字节），且为偶数长度\n" +
                        "- 确保解密密钥与加密密钥完全一致");
            }
        });

        // 密文篡改测试按钮事件
        tamperBtn.addActionListener(e -> {
            try {
                String plainStr = plainField.getText().trim();
                String keyHex = keyField.getText().trim();
                String ivHex = ivField.getText().trim();
                if (plainStr.length() < 4) throw new IllegalArgumentException("明文长度需≥4字符（确保生成≥2个加密分组）");
                if (keyHex.length() != 4 || ivHex.length() != 4) throw new IllegalArgumentException("密钥和IV必须为4个十六进制字符（16位）");

                byte[] plain = plainStr.getBytes(StandardCharsets.US_ASCII);
                byte[] key = SAESCore.hexToBytes(keyHex);
                byte[] iv = SAESCore.hexToBytes(ivHex);
                byte[] normalCipher = SAESCore.encryptCBC(plain, key, iv);
                byte[] normalPlain = SAESCore.decryptCBC(normalCipher, key);
                String normalPlainStr = new String(normalPlain, StandardCharsets.US_ASCII);

                byte[] tamperedCipher = Arrays.copyOf(normalCipher, normalCipher.length);
                if (tamperedCipher.length > 4) {
                    tamperedCipher[2] ^= 0x01;
                    tamperedCipher[3] ^= 0x08;
                } else {
                    throw new IllegalArgumentException("明文过短，生成的密文仅含IV，无法篡改测试");
                }
                byte[] tamperedPlain = SAESCore.decryptCBC(tamperedCipher, key);
                String tamperedPlainStr = new String(tamperedPlain, StandardCharsets.US_ASCII);

                resultArea.setText("=== CBC模式篡改测试成功 ===\n" +
                        "1. 测试前提：\n" +
                        "   - 明文：" + plainStr + "\n" +
                        "   - 密钥：" + keyHex + "，IV：" + ivHex + "\n" +
                        "2. 正常解密结果：\n" +
                        "   - 密文（含IV）：" + SAESCore.bytesToHex(normalCipher) + "\n" +
                        "   - 明文：" + normalPlainStr + "\n" +
                        "3. 篡改操作：\n" +
                        "   - 篡改位置：密文第3-4字节（第1个数据分组，跳过IV）\n" +
                        "   - 篡改后密文：" + SAESCore.bytesToHex(tamperedCipher) + "\n" +
                        "4. 篡改后解密结果：\n" +
                        "   - 明文：" + tamperedPlainStr + "\n" +
                        "   - 关键结论：CBC模式下，单个分组篡改导致“当前分组+下一分组”错乱（链式效应），后续分组恢复正常");
            } catch (Exception ex) {
                resultArea.setText("=== CBC模式篡改测试失败 ===\n" +
                        "错误原因：" + ex.getMessage() + "\n" +
                        "建议：输入长度≥4的明文（如\"CBC Mode Test With Long Text\"），确保生成多个分组");
            }
        });

        return panel;
    }

    // 主函数（启动GUI）
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            SAESGUI gui = new SAESGUI();
            gui.setVisible(true);
        });
    }
}