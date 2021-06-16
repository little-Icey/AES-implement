#ifndef _AES_H__
#define _AES_H__

#include "table.h"

extern unsigned char key[4][4];
extern unsigned char extendKey[4][44];

void XOR(unsigned char* a, unsigned char* b, int len);

void hexToByte(char* plainStr, unsigned char* plainByte, int len);

void byteToHex(unsigned char* plainByte, char* plainStr, int len);

void changeToArray(unsigned char* str, unsigned char(*array)[4]);

void changeFromArray(unsigned char(*array)[4], unsigned char* str);

// �ֽ��滻�任
void subByte(unsigned char* plainArray);

// ���ֽ��滻�任
void reSubByte(unsigned char(*cipher)[4]);

void reverse(unsigned char* arr, int start, int end);

void leftShift(unsigned char* arr, int len, int shift);

// ����λ�任
void shiftRows(unsigned char(*plain)[4]);

void shiftRowsNew(unsigned int* plainArray);

// GF(2^128)���ϳ˷�
char GF_multiply(unsigned char left, unsigned char right);

// �л�ϱ任
void mixColumns(unsigned char(*plain)[4]);

// ������λ�任
void reMixColumns(unsigned char(*cipher)[4]);

void keySub(unsigned char(*extendKey)[44], unsigned int col);

void gFunction(unsigned char(*extendKey)[44], unsigned int col);

void generateExtendKey(const unsigned char(*key)[4], unsigned char(*extendKey)[44]);

void addRoundKey(unsigned char(*plain)[4], unsigned char(*extendKey)[44], unsigned int col);

void encrypt(unsigned char* plain, unsigned char* cipher);

void decrypt(unsigned char* cipher, unsigned char* plain);
#endif _AES_H__
