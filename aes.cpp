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
param len �ַ�����ĳ���*/
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
param len �ֽ�����ĳ���*/
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
plain ����Ϊ�ֽ����飬��ʹ��char������ʾ
�����е�Ԫ��Ϊʮ��������
*/
//void subByte(unsigned char* plain) {
//	for (int i = 0; i < 16; i++) {
//		plain[i] = s_box[plain[i] >> 4][plain[i] & 0xf];
//	}
//}

void subByte(unsigned char *plainArray) {
    //for (int i = 0; i < 4; i++) // ��
    //{
    //    for (int j = 0; j < 4; j++) // ��
    //    {
    //        plain[j][i] = s_box[plain[j][i] >> 4][plain[j][i] & 0xf];
    //    }
    //}
    for (int i = 0; i < 16; i++)
    {
        plainArray[i] = s_box[plainArray[i] >> 4][plainArray[i] & 0xf];
    }
}

// ���ֽ��滻�任
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

//����ԭ���飺 1 2 3 4 5 6 7 ��Ҫ����4�Σ���ô������Ҫ�Ľ���ǣ� 5 6 7 1 2 3 4��
//1.��1234���� ��� 4321
//2.��567���� ��� 765
//3.��������������ƴ�ӣ� 4321765
//4.�������ƴ�ӵ��������ã� 5671234 �ͳ���������Ҫ�Ľ���ˡ�
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

// ������λ�任
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

// GF(2^128)���ϳ˷�
char GF_multiply(unsigned char left, unsigned char right) {
    unsigned char ans = 0;

    while (left)
    {
        if (left & 0x01)
            ans ^= right;

        left = left >> 1;
        if (right & 0x80)
        {
            right = right << 1; // ���Ʋ���
            right ^= 0x1b; // ���b7=1�����ȥm(x)
        }
        else
            right = right << 1;
    }
    return ans;
}

// �л�ϱ任
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

/*�ɹ�����ԿWK����4*(Nr+1)���ֵ���չ��Կ����44*4=176���ֽڣ�����չ��ԿextendKey��ʾΪextendKey[4][44]*/
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
        // �Ե�4*i -1 ���ֽ���G��������
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

    // ��k[0]�������
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