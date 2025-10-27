import java.util.Arrays;

public class SAES {
    // S盒与逆S盒
    private static final int[] S_BOX = {
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    };
    private static final int[] INV_S_BOX = {
        0xA, 0x5, 0x9, 0xB,
        0x1, 0x7, 0x8, 0xF,
        0x6, 0x0, 0x2, 0x3,
        0xC, 0x4, 0xD, 0xE
    };

    // 轮常数
    private static final int RCON1 = 0x80;
    private static final int RCON2 = 0x30;


    // GF(2⁴)有限域乘法，模多项式x⁴+x+1
    private static int gfMult(int a, int b) {
        if (a == 0 || b == 0) return 0;
        int result = 0;
        for (int i = 0; i < 4; i++) {
            if ((b & (1 << (3 - i))) != 0) {
                result ^= (a << i);
            }
        }
        for (int i = 7; i >= 4; i--) {
            if ((result & (1 << i)) != 0) {
                result ^= (0b10011 << (i - 4));
            }
        }
        return result & 0xF;
    }


    // 16位密钥扩展为3个16位轮密钥
    public static int[] keyExpansion(int key16) {
        int w0 = (key16 >> 8) & 0xFF;
        int w1 = key16 & 0xFF;

        int w2 = w0 ^ gFunc(w1, RCON1);
        int w3 = w2 ^ w1;
        int w4 = w2 ^ gFunc(w3, RCON2);
        int w5 = w4 ^ w3;

        return new int[]{
            (w0 << 8) | w1,
            (w2 << 8) | w3,
            (w4 << 8) | w5
        };
    }

    // 密钥扩展辅助函数：RotNib + SubNib + RCON
    private static int gFunc(int w, int rcon) {
        int rot = ((w & 0x0F) << 4) | ((w >> 4) & 0x0F);
        int sub = (S_BOX[(rot >> 4) & 0x0F] << 4) | S_BOX[rot & 0x0F];
        return sub ^ rcon;
    }


    // 16位数据转换为2×2半字节矩阵（按列排列）
    private static int[][] dataToState(int data16) {
        return new int[][]{
            {(data16 >> 12) & 0x0F, (data16 >> 4) & 0x0F},
            {(data16 >> 8) & 0x0F, data16 & 0x0F}
        };
    }

    // 2×2半字节矩阵转换为16位数据
    private static int stateToData(int[][] state) {
        return (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1];
    }


    // 半字节代替
    private static int[][] subNibbles(int[][] state) {
        int[][] newState = new int[2][2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                newState[i][j] = S_BOX[state[i][j]];
            }
        }
        return newState;
    }

    // 逆半字节代替
    private static int[][] invSubNibbles(int[][] state) {
        int[][] newState = new int[2][2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                newState[i][j] = INV_S_BOX[state[i][j]];
            }
        }
        return newState;
    }

    // 行移位
    private static int[][] shiftRows(int[][] state) {
        return new int[][]{
            {state[0][0], state[0][1]},
            {state[1][1], state[1][0]}
        };
    }

    // 逆行移位
    private static int[][] invShiftRows(int[][] state) {
        return shiftRows(state);
    }

    // 列混淆：矩阵乘法[[1,4],[4,1]]
    private static int[][] mixColumns(int[][] state) {
        int s00 = state[0][0], s01 = state[0][1];
        int s10 = state[1][0], s11 = state[1][1];
        return new int[][]{
            {gfMult(1, s00) ^ gfMult(4, s10), gfMult(1, s01) ^ gfMult(4, s11)},
            {gfMult(4, s00) ^ gfMult(1, s10), gfMult(4, s01) ^ gfMult(1, s11)}
        };
    }

    // 逆列混淆：矩阵乘法[[9,2],[2,9]]
    private static int[][] invMixColumns(int[][] state) {
        int s00 = state[0][0], s01 = state[0][1];
        int s10 = state[1][0], s11 = state[1][1];
        return new int[][]{
            {gfMult(9, s00) ^ gfMult(2, s10), gfMult(9, s01) ^ gfMult(2, s11)},
            {gfMult(2, s00) ^ gfMult(9, s10), gfMult(2, s01) ^ gfMult(9, s11)}
        };
    }

    // 轮密钥加：状态与轮密钥逐位异或
    private static int[][] addRoundKey(int[][] state, int roundKey16) {
        int[][] keyState = dataToState(roundKey16);
        int[][] newState = new int[2][2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                newState[i][j] = state[i][j] ^ keyState[i][j];
            }
        }
        return newState;
    }


    // 基础加密：16位明文+16位密钥→16位密文
    public static int encrypt16(int plaintext16, int key16) {
        int[] roundKeys = keyExpansion(key16);
        int[][] state = dataToState(plaintext16);

        // 第0轮：轮密钥加（K0）
        state = addRoundKey(state, roundKeys[0]);

        // 第1轮：SubNibbles → ShiftRows → MixColumns → AddRoundKey（K1）
        state = subNibbles(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, roundKeys[1]);

        // 第2轮：SubNibbles → ShiftRows → AddRoundKey（K2）
        state = subNibbles(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKeys[2]);

        return stateToData(state);
    }


    // 基础解密：16位密文+16位密钥→16位明文
    public static int decrypt16(int ciphertext16, int key16) {
        int[] roundKeys = keyExpansion(key16);
        int[][] state = dataToState(ciphertext16);

        // 第0轮：轮密钥加（K2）
        state = addRoundKey(state, roundKeys[2]);

        // 第1轮：InvShiftRows → InvSubNibbles → AddRoundKey（K1）→ InvMixColumns
        state = invShiftRows(state);
        state = invSubNibbles(state);
        state = addRoundKey(state, roundKeys[1]);
        state = invMixColumns(state);

        // 第2轮：InvShiftRows → InvSubNibbles → AddRoundKey（K0）
        state = invShiftRows(state);
        state = invSubNibbles(state);
        state = addRoundKey(state, roundKeys[0]);

        return stateToData(state);
    }


    // 字符串→16位数据块数组（2字节分组，不足补0x00）
    private static int[] strToBlocks(String s) {
        int blockCount = (s.length() + 1) / 2;
        int[] blocks = new int[blockCount];
        for (int i = 0; i < blockCount; i++) {
            int b1 = (i * 2 < s.length()) ? (int) s.charAt(i * 2) : 0x00;
            int b2 = (i * 2 + 1 < s.length()) ? (int) s.charAt(i * 2 + 1) : 0x00;
            blocks[i] = (b1 << 8) | b2;
        }
        return blocks;
    }

    // 16位数据块数组→字符串（过滤补位0x00）
    private static String blocksToStr(int[] blocks) {
        StringBuilder sb = new StringBuilder();
        for (int block : blocks) {
            char c1 = (char) ((block >> 8) & 0xFF);
            char c2 = (char) (block & 0xFF);
            if (c1 != 0x00) sb.append(c1);
            if (c2 != 0x00) sb.append(c2);
        }
        return sb.toString();
    }

    // 字符串加密
    public static String encryptStr(String plaintext, int key16) {
        int[] blocks = strToBlocks(plaintext);
        int[] cipherBlocks = Arrays.stream(blocks)
                .map(block -> encrypt16(block, key16))
                .toArray();
        return blocksToStr(cipherBlocks);
    }

    // 字符串解密
    public static String decryptStr(String ciphertext, int key16) {
        int[] blocks = strToBlocks(ciphertext);
        int[] plainBlocks = Arrays.stream(blocks)
                .map(block -> decrypt16(block, key16))
                .toArray();
        return blocksToStr(plainBlocks);
    }


    // 双重加密：32位密钥（K1+K2）→ E(K2, E(K1, P))
    public static int doubleEncrypt(int plaintext16, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF;
        int k2 = key32 & 0xFFFF;
        return encrypt16(encrypt16(plaintext16, k1), k2);
    }

    // 双重解密：D(K1, D(K2, C))
    public static int doubleDecrypt(int ciphertext16, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF;
        int k2 = key32 & 0xFFFF;
        return decrypt16(decrypt16(ciphertext16, k2), k1);
    }


    // 中间相遇攻击：通过明密文对查找32位双重加密密钥
    public static Integer meetInTheMiddle(int plaintext16, int ciphertext16) {
        int[] forwardMap = new int[0x10000];
        for (int k1 = 0; k1 < 0x10000; k1++) {
            forwardMap[k1] = encrypt16(plaintext16, k1);
        }

        for (int k2 = 0; k2 < 0x10000; k2++) {
            int midVal = decrypt16(ciphertext16, k2);
            for (int k1 = 0; k1 < 0x10000; k1++) {
                if (forwardMap[k1] == midVal) {
                    return (k1 << 16) | k2;
                }
            }
        }
        return null;
    }


    // 三重加密：32位密钥（K1+K2），EDE模式
    public static int tripleEncrypt(int plaintext16, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF;
        int k2 = key32 & 0xFFFF;
        int step1 = encrypt16(plaintext16, k2);
        int step2 = decrypt16(step1, k1);
        int step3 = encrypt16(step2, k2);
        return step3;
    }

    // 三重解密：32位密钥（K1+K2），DDE模式
    public static int tripleDecrypt(int ciphertext16, int key32) {
        int k1 = (key32 >> 16) & 0xFFFF;
        int k2 = key32 & 0xFFFF;
        int step1 = decrypt16(ciphertext16, k2);
        int step2 = encrypt16(step1, k1);
        int step3 = decrypt16(step2, k2);
        return step3;
    }


    // CBC加密：需16位IV
    public static String cbcEncrypt(String plaintext, int key16, int iv16) {
        int[] plainBlocks = strToBlocks(plaintext);
        int[] cipherBlocks = new int[plainBlocks.length];
        int prevBlock = iv16;

        for (int i = 0; i < plainBlocks.length; i++) {
            int xorBlock = plainBlocks[i] ^ prevBlock;
            cipherBlocks[i] = encrypt16(xorBlock, key16);
            prevBlock = cipherBlocks[i];
        }
        return blocksToStr(cipherBlocks);
    }

    // CBC解密：需16位IV
    public static String cbcDecrypt(String ciphertext, int key16, int iv16) {
        int[] cipherBlocks = strToBlocks(ciphertext);
        int[] plainBlocks = new int[cipherBlocks.length];
        int prevBlock = iv16;

        for (int i = 0; i < cipherBlocks.length; i++) {
            int decryptBlock = decrypt16(cipherBlocks[i], key16);
            plainBlocks[i] = decryptBlock ^ prevBlock;
            prevBlock = cipherBlocks[i];
        }
        return blocksToStr(plainBlocks);
    }

    // CBC密文篡改：修改指定索引的密文块
    public static String tamperCbcCiphertext(String ciphertext, int tamperIndex, int tamperVal) {
        int[] blocks = strToBlocks(ciphertext);
        if (tamperIndex >= 0 && tamperIndex < blocks.length) {
            blocks[tamperIndex] ^= tamperVal;
        }
        return blocksToStr(blocks);
    }


    // 十六进制字符串转整数
    public static Integer hexToInt(String hexStr) {
        if (hexStr == null || hexStr.trim().isEmpty()) return null;
        try {
            return Integer.parseInt(hexStr.trim(), 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    // 整数转指定长度十六进制字符串
    public static String intToHex(int num, int bitLength) {
        String format = (bitLength == 16) ? "%04X" : "%08X";
        return String.format(format, num);
    }
}