#include<cstdio>
#include<cstdlib>
#include<cstring>
#include "aes.h"
#include "table.h"

unsigned char key[4][4];
unsigned char extendKey[4][44];


void XOR(unsigned char* a, unsigned char* b, int len) {
    for (int i = 0; i < len; i++)
    {
        a[i] ^= b[i];
    }
}


/*
param len 字符数组的长度*/
void hexToByte(char* plainStr, unsigned char* plainByte, int len) {
    unsigned char ascii[2];
    for (int i = 0, j=0; i < len; i+=2,j++)
    {
        if (plainStr[i] >= '0' && plainStr[i] <= '9')
            ascii[0] = plainStr[i] - '0';
        else
            ascii[0] = plainStr[i] - 'A' + 10;
        if (plainStr[i + 1] >= '0' && plainStr[i + 1] <= '9')
            ascii[1] = plainStr[i + 1] - '0';
        else
            ascii[1] = plainStr[i + 1] - 'A' + 10;
        plainByte[j] = (ascii[0] << 4) + ascii[1];
    }
}

/*
param len 字节数组的长度*/
void byteToHex(unsigned char* plainByte, char* plainStr, int len) {
    unsigned char tmp[2];
    for (int i = 0, j = 0; i < len; i++, j += 2) {
        tmp[0] = plainByte[i] >> 4;
        tmp[1] = plainByte[i] & 0xf;
        if (tmp[0] >= 0 && tmp[0] <= 9)
            plainStr[j] = tmp[0] + '0';
        else
            plainStr[j] = tmp[0] - 10 + 'A';
        if (tmp[1] >= 0 && tmp[1] <= 9)
            plainStr[j+1] = tmp[1] + '0';
        else
            plainStr[j+1] = tmp[1] - 10 + 'A';
    }
}

void changeToArray(unsigned char* str, unsigned char(*array)[4]) {
    for (int col = 0; col <4; col++)
        for (int row = 0; row < 4; row++)
            array[row][col] = str[4 * col + row];
}

void changeFromArray(unsigned char(*array)[4], unsigned char* str) {
    for (int col = 0; col < 4; col++)
        for (int row = 0; row < 4; row++)
            str[4 * col + row] = array[row][col];
}

/*
plain 数组为字节数组，故使用char型来表示
数组中的元素为十六进制数
*/
//void subByte(unsigned char* plain) {
//	for (int i = 0; i < 16; i++) {
//		plain[i] = s_box[plain[i] >> 4][plain[i] & 0xf];
//	}
//}

void subByte(unsigned char *plainArray) {
    //for (int i = 0; i < 4; i++) // 列
    //{
    //    for (int j = 0; j < 4; j++) // 行
    //    {
    //        plain[j][i] = s_box[plain[j][i] >> 4][plain[j][i] & 0xf];
    //    }
    //}
    for (int i = 0; i < 16; i++)
    {
        plainArray[i] = s_box[plainArray[i] >> 4][plainArray[i] & 0xf];
    }
}

// 逆字节替换变换
//void reSubByte(unsigned char* cipher) {
//	for (int i = 0; i < 16; i++){
//		cipher[i] = re_s_box[cipher[i] >> 4][cipher[i] & 0xf];
//	}
//}

void reSubByte(unsigned char(*cipher)[4]) {
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            cipher[j][i] = re_s_box[cipher[j][i] >> 4][cipher[j][i] & 0xf];
        }
    }
}

void reverse(unsigned char* arr, int start, int end) {
    for (; start < end; start++, end--) {
        unsigned char s = arr[end];
        arr[end] = arr[start];
        arr[start] = s;
    }
}

//假如原数组： 1 2 3 4 5 6 7 须要左移4次，那么我们想要的结果是： 5 6 7 1 2 3 4。
//1.将1234逆置 变成 4321
//2.将567逆置 变成 765
//3.将两个逆置数组拼接： 4321765
//4.将这个已拼接的数组逆置： 5671234 就成了我们想要的结果了。
void leftShift(unsigned char* arr, int len, int shift) {
    shift = shift % len;
    reverse(arr, 0, shift - 1);
    reverse(arr, shift, len - 1);
    reverse(arr, 0, len - 1);
}


void shiftRows(unsigned char(*plain)[4]) {
    for (int i = 0; i < 4; i++)
    {
        leftShift(plain[i], 4, i);
    }
}

void shiftRowsNew(unsigned int* plainArray) {
    plainArray[1] = (plainArray[1] >> 8) | (plainArray[1] << 24);
    plainArray[2] = (plainArray[2] >> 16) | (plainArray[2] << 16);
    plainArray[3] = (plainArray[3] >> 24) | (plainArray[3] << 8);
}

// 逆行移位变换
//void reShiftRows(unsigned char* cipher) {
//    for (int i = 0; i < 4; i++){
//        leftShift(cipher + (i << 2), 4, (4 - i));
//    }
//}

void reShiftRows(unsigned char(*cipher)[4]) {
    for (int i = 0; i < 4; i++)
    {
        leftShift(cipher[i], 4, (4 - i));
    }
}

// GF(2^128)域上乘法
char GF_multiply(unsigned char left, unsigned char right) {
    unsigned char ans = 0;

    while (left)
    {
        if (left & 0x01)
            ans ^= right;

        left = left >> 1;
        if (right & 0x80)
        {
            right = right << 1; // 左移操作
            right ^= 0x1b; // 如果b7=1，则减去m(x)
        }
        else
            right = right << 1;
    }
    return ans;
}

// 列混合变换
void mixColumns(unsigned char(*plain)[4]) {
    unsigned char temp[4][4];
    memcpy(temp, plain, 16);
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            plain[i][j] =
                GF_multiply(mixColumnsArray[i][0], temp[0][j]) ^
                GF_multiply(mixColumnsArray[i][1], temp[1][j]) ^
                GF_multiply(mixColumnsArray[i][2], temp[2][j]) ^
                GF_multiply(mixColumnsArray[i][3], temp[3][j]);
        }
    }
}

void reMixColumns(unsigned char(*cipher)[4]) {
    unsigned char temp[4][4];
    memcpy(temp, cipher, 16);
    for(int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            cipher[i][j] =
                GF_multiply(reMixColumnsArray[i][0], temp[0][j]) ^
                GF_multiply(reMixColumnsArray[i][1], temp[1][j]) ^
                GF_multiply(reMixColumnsArray[i][2], temp[2][j]) ^
                GF_multiply(reMixColumnsArray[i][3], temp[3][j]);
        }
}

/*由工作密钥WK产生4*(Nr+1)个字的扩展密钥，即44*4=176个字节，将扩展密钥extendKey表示为extendKey[4][44]*/
void keySub(unsigned char(*extendKey)[44], unsigned int col) {
    for (int i = 0; i < 4; i++)
        extendKey[i][col] = s_box[extendKey[i][col] >> 4][extendKey[i][col] & 0xf];
}

void gFunction(unsigned char(*extendKey)[44], unsigned int col) {
    for (int i = 0; i < 4; i++)
        extendKey[i][col] = extendKey[(i + 1) % 4][col - 1];
    keySub(extendKey, col);
    extendKey[0][col] ^= Rcon[col / 4];
}

void generateExtendKey(const unsigned char(*key)[4], unsigned char(*extendKey)[44]) {
    for (int i = 0; i < 16; i++)
        extendKey[i & 0x03][i >> 2] = key[i & 0x03][i >> 2];
    for (int i = 1; i < 11; i++)
    {
        // 对第4*i -1 个字进行G函数处理
        gFunction(extendKey, 4 * i);

        for (int k = 0; k < 4; k++)
            extendKey[k][4 * i] ^= extendKey[k][4 * (i - 1)];
        for (int j = 1; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                extendKey[k][4 * i + j] = extendKey[k][4 * i + j - 1] ^ extendKey[k][4 * (i - 1) + j];
            }
        }
    }
}

void addRoundKey(unsigned char(*plain)[4], unsigned char(*extendKey)[44], unsigned int col) {
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            plain[i][j] ^= extendKey[i][col + j];
        }
    }
}

void encrypt(unsigned char *plain, unsigned char *cipher) {
    unsigned char plainArray[4][4] = { '\x00' };
    changeToArray(plain, plainArray);

    // 与k[0]进行异或
    addRoundKey(plainArray, extendKey, 0);

    for (int i = 1; i < 10; i++)
    {
        subByte((unsigned char*)plainArray);
        shiftRows(plainArray);
        mixColumns(plainArray);
        addRoundKey(plainArray, extendKey, 4 * i);
    }

    subByte((unsigned char*)plainArray);
    shiftRows(plainArray);
    addRoundKey(plainArray, extendKey, 4*10);

    changeFromArray(plainArray, cipher);
    
}


void decrypt(unsigned char* cipher, unsigned char* plain) {
    unsigned char cipherArray[4][4] = { '\x00' };
    changeToArray(cipher, cipherArray);

    addRoundKey(cipherArray, extendKey, 4*10);
    reShiftRows(cipherArray);
    reSubByte(cipherArray);

    for (int i = 9; i > 0; i--) {
        addRoundKey(cipherArray, extendKey, 4 * i);
        reMixColumns(cipherArray);
        reShiftRows(cipherArray);
        reSubByte(cipherArray);
    }

    addRoundKey(cipherArray, extendKey, 0);
    changeFromArray(cipherArray, plain);
}