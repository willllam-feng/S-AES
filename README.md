# S-AES

项目介绍

本项目基于《密码编码学与网络安全 —— 原理与实践（第 8 版）》附录 D 的简化 AES（S-AES）算法，实现了完整的加解密功能及 GUI 交互界面，满足 "信息安全导论" 课程作业 2 的全部 5 个关卡要求，支持多场景加密需求与安全测试。

功能清单

第 1 关：基础加解密

输入：16 位十六进制明文 / 密文、16 位十六进制密钥

<img width="1277" height="817" alt="60a6ab42a310997e0ac986117e7faf57" src="https://github.com/user-attachments/assets/dafbb3f1-922b-4d8f-a4c5-1d5569530778" />

输出：16 位十六进制密文 / 明文

<img width="1277" height="817" alt="2cf4513bbea7fb912941bdd275797b5d" src="https://github.com/user-attachments/assets/f59eca45-cd7d-4c8e-af8c-709c0b2fad4c" />

核心：严格遵循 S-AES 算法流程（密钥扩展、半字节代替、行位移、列混淆、轮密钥加）

第 2 关：交叉测试支持

算法标准化实现，确保不同小组使用相同密钥加密同一明文时，得到一致密文

支持跨平台解密：接收其他组加密的密文，可正确还原明文

第 3 关：ASCII 字符串扩展

输入：任意 ASCII 可显字符串、16 位密钥
<img width="1277" height="817" alt="fee20d9a17179e668073d23c96b2ffa7" src="https://github.com/user-attachments/assets/31053c1a-0fe0-4666-a0ce-d896f600de51" />

处理：自动按 2 字节分组，不足补 0x00

输出：加密后 ASCII 字符串（可能为乱码），解密后还原原始字符串
<img width="1277" height="817" alt="cd349048348b09220fed3f3feb8d81ec" src="https://github.com/user-attachments/assets/b4c2d71c-76b3-4161-8de3-bb8f1d471cf8" />

第 4 关：多重加密

双重加密 / 解密：32 位密钥（K1+K2），流程：E (K2,E (K1,P)) / D (K1,D (K2,C))
<img width="1277" height="817" alt="176666f9af399a8145a4eb6841e94c82" src="https://github.com/user-attachments/assets/0a19e8d6-ca9e-4dac-919c-a7f6c3af5618" />
<img width="1277" height="817" alt="25d8d47ff763e6ffda16bf0849be1c55" src="https://github.com/user-attachments/assets/c58135f4-9844-4298-b077-878668ae3efe" />
<img width="1277" height="817" alt="3b620a092357a19bd6fcf30531a5b394" src="https://github.com/user-attachments/assets/a6b7e345-1807-42c3-b032-0a07bfeb3a80" />
三重加密 / 解密：32 位密钥（K1+K2），EDE 模式
<img width="1277" height="817" alt="eea22a6833e80c99091f77507d7e586b" src="https://github.com/user-attachments/assets/5ef7a1c8-c993-456e-9350-1f80c1958669" />

<img width="1277" height="817" alt="8d9da8cfc3836286a1a29f031da13199" src="https://github.com/user-attachments/assets/1928728c-29af-4029-825a-f2503297d430" />


中间相遇攻击：通过 16 位明密文对，破解 32 位双重加密密钥

第 5 关：CBC 工作模式

支持长明文加密：基于 16 位初始向量（IV）的分组链模式


密文篡改测试：修改指定密文分组，验证解密后的链式错误效应

输入：ASCII 字符串、16 位密钥、16 位 IV；输出：加密 / 解密结果
<img width="1277" height="817" alt="851328fa73bec50f37088b3d29b7b9a5" src="https://github.com/user-attachments/assets/70827e76-d3a5-4161-83d2-9ee7dd728d7d" />
<img width="1277" height="817" alt="851328fa73bec50f37088b3d29b7b9a5" src="https://github.com/user-attachments/assets/fbc16823-3586-444c-9a07-4cbd72708938" />

=== CBC模式篡改测试成功 ===
1. 测试前提：
   - 明文：1234700387EF371785A5645A79B512D9FB49AE5E68689D38CD9DBE35B1CC
   - 密钥：2D55，IV：1234
2. 正常解密结果：
   - 密文（含IV）：12 34 C9 CB BF 6E F3 FD CC 52 F7 AC 29 E1 A6 34 5D 3C 10 9E F3 87 0B 44 4B 52 16 CF E0 C6 D2 7F 01 C9 AE DB DA 4B 72 61 3C 75 A4 A7 C0 A3 95 89 68 AA 5D 74 0D B6 B8 D0 8D 7B 9A 90 A4 69
   - 明文：1234700387EF371785A5645A79B512D9FB49AE5E68689D38CD9DBE35B1CC
3. 篡改操作：
   - 篡改位置：密文第3-4字节（第1个数据分组，跳过IV）
   - 篡改后密文：12 34 C8 C3 BF 6E F3 FD CC 52 F7 AC 29 E1 A6 34 5D 3C 10 9E F3 87 0B 44 4B 52 16 CF E0 C6 D2 7F 01 C9 AE DB DA 4B 72 61 3C 75 A4 A7 C0 A3 95 89 68 AA 5D 74 0D B6 B8 D0 8D 7B 9A 90 A4 69
4. 篡改后解密结果：
   - 明文：��2<700387EF371785A5645A79B512D9FB49AE5E68689D38CD9DBE35B1CC
   - 关键结论：CBC模式下，单个分组篡改导致“当前分组+下一分组”错乱（链式效应），后续分组恢复正常

环境要求

JDK 8 及以上

无需额外依赖（仅使用 Java Swing、基础类库）


使用指南

1. 编译运行
   
bash

# 编译源代码

javac SAES.java SAES_GUI.java

# 启动GUI工具

java SAES_GUI

2. GUI 操作步骤
   
选择功能：从下拉框选择所需功能（如 "16 位加解密"、"CBC 模式加密"）

输入参数：

明文 / 密文：基础加解密输入 16 位十六进制，字符串功能输入 ASCII 字符，中间相遇攻击输入 "明文，密文" 格式

密钥：16 位（4 个十六进制字符）或 32 位（8 个十六进制字符），按功能要求输入

IV：仅 CBC 模式需输入 16 位十六进制（4 个字符）

执行操作：点击 "执行操作" 按钮，结果将显示在下方结果区域

测试要求

第 1 关：基础测试

输入示例：明文0000、密钥2D55

验证：加密后密文一致性，解密后还原原始明文

第 2 关：交叉测试

与其他小组约定相同密钥（如1234）和明文（如ABCD）

验证：双方加密得到相同密文，互解密可还原明文
第 3 关：扩展功能测试

输入字符串HelloS-AES、密钥3F7A

验证：加密后输出乱码，解密后还原原始字符串

第 4 关：多重加密测试

双重加密：明文0000、32 位密钥2D55AABB，验证加密后密文

中间相遇攻击：输入明密文对0000,XXXX（XXXX 为双重加密密文），验证密钥破解结果

第 5 关：CBC 模式测试

输入明文CBC Mode Test、密钥2D55、IV1234

篡改测试：使用tamperCbcCiphertext方法修改密文，验证解密后前序分组错乱、后续分组正常的链式效应

测试结果汇总

=== 基础加解密测试 ===
明文（16位）：00 00
密钥（16位）：2D 55
密文（16位）：B8 E1
解密后明文：00 00
基础测试是否通过：true

=== ASCII字符串测试 ===
明文字符串：HelloS-AES
密文字节（十六进制）：E9 01 56 CD 37 6B 18 21 BD 80
解密后字符串：HelloS-AES
字符串测试是否通过：true

=== CBC模式测试 ===
原始明文：CBC Mode Test
CBC解密后：CBC Mode Test
篡改密文后解密：K?B Mode Test
篡改影响：前两个明文块错乱（CBC链式效应）

