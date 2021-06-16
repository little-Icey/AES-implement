#include<iostream>
#include<fstream>
#include<ctime>
#include "mode.h"
#include "aes.h"

using namespace std;

void ECB_test(char* plainfile, char* cipherfile) {
	clock_t start, end;
	long fsize;
	char* pbuffer;
	char* cbuffer;
	unsigned char* plainByte;
	unsigned char* cipherByte;
	size_t result;
	FILE* fp;

	fp = fopen(plainfile, "rb");
	if (fp == NULL) {
		printf("open error\n");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	pbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	cbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	fread(pbuffer, 1, fsize, fp);
	pbuffer[fsize] = '\x00';
	cbuffer[fsize] = '\x00';
	fclose(fp);

	plainByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));
	cipherByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));

	hexToByte(pbuffer, plainByte, fsize);

	start = clock();
	for (int i = 0; i < (fsize/2); i+=16)
	{
		encrypt(plainByte + i, cipherByte + i);
	}
	end = clock();


	byteToHex(cipherByte, cbuffer, fsize / 2);
	cout << "[*] 加密结果：" << cbuffer << endl;

	ofstream out;
	out.open(cipherfile);
	out << cbuffer;
	out.close();

	memset(plainByte, 0, fsize / 2);
	memset(pbuffer, 0, fsize);

	for (int i = 0; i < fsize/2; i+=16)
	{
		decrypt(cipherByte + i, plainByte + i);
	}

	byteToHex(plainByte, pbuffer, fsize / 2);
	cout << "[*] 解密结果:" << pbuffer << endl;
	cout << "[+] Running time: " << ((double)end - start) << "ms\n";

	free(pbuffer);
	free(cbuffer);
	free(plainByte);
	free(cipherByte);

}

void CBC_enc(unsigned char* plainByte, unsigned char* cipherByte, unsigned char* ivByte, int len) {
	unsigned char tmpPl[16];
	unsigned char tmpCi[16];

	memcpy(tmpPl, plainByte, 16);
	XOR(tmpPl, ivByte, 16);
	encrypt(tmpPl, cipherByte);
	memcpy(tmpCi, cipherByte, 16);
	for (int i = 16; i < len; i+=16)
	{
		XOR(tmpCi, plainByte + i, 16);
		encrypt(tmpCi, cipherByte + i);
		memcpy(tmpCi, cipherByte + i, 16);
	}
}

void CBC_dec(unsigned char* cipherByte, unsigned char* plainByte, unsigned char* ivByte, int len) {
	unsigned char tmpPl[16];
	decrypt(cipherByte, tmpPl);
	XOR(tmpPl, ivByte, 16);
	memcpy(plainByte, tmpPl, 16);
	for (int i = 16; i < len; i+=16)
	{
		decrypt(cipherByte + i, tmpPl);
		XOR(tmpPl, cipherByte + i - 16, 16);
		memcpy(plainByte + i, tmpPl, 16);
	}
}

void CBC_test(char* plainfile, char* cipherfile, char* ivStr) {
	clock_t start, end;
	long fsize;
	char* pbuffer;
	char* cbuffer;
	unsigned char* plainByte;
	unsigned char* cipherByte;
	unsigned char ivByte[16];
	size_t result;
	FILE* fp;

	fp = fopen(plainfile, "rb");
	if (fp == NULL) {
		printf("open error\n");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	pbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	cbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	fread(pbuffer, 1, fsize, fp);
	pbuffer[fsize] = '\x00';
	cbuffer[fsize] = '\x00';
	fclose(fp);
	plainByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));
	cipherByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));

	hexToByte(ivStr, ivByte, 32);
	hexToByte(pbuffer, plainByte, fsize);
	start = clock();
	CBC_enc(plainByte, cipherByte, ivByte, fsize/2);
	end = clock();
	byteToHex(cipherByte, cbuffer, fsize / 2);
	cout << "[*] 加密结果：" << cbuffer << endl;

	ofstream out;
	out.open(cipherfile);
	out << cbuffer;
	out.close();

	memset(plainByte, 0, fsize / 2);
	memset(pbuffer, 0, fsize);
	CBC_dec(cipherByte, plainByte, ivByte, fsize / 2);
	byteToHex(plainByte, pbuffer, fsize / 2);
	cout << "[*] 解密结果:" << pbuffer << endl;
	cout << "[*] Running time: " << ((double)end - start) / 1000 << "s\n";

	free(pbuffer);
	free(cbuffer);
	free(plainByte);
	free(cipherByte);

}

// 32位操作模式，也就是4个字节
void CFB_enc(unsigned char* plainByte, unsigned char* cipherByte, unsigned char* ivByte, int len) {
	unsigned char enc_reg[16];
	unsigned char tmpIv[16];

	memcpy(tmpIv, ivByte, 16);
	encrypt(tmpIv, enc_reg);
	XOR(enc_reg, plainByte, 4);
	memcpy(cipherByte, enc_reg, 4);

	for (int i = 4; i < len; i+=4)
	{
		leftShift(tmpIv, 16, 4);
		memcpy(tmpIv + 12, cipherByte + i - 4, 4);
		encrypt(tmpIv, enc_reg);
		XOR(enc_reg, plainByte + i, 4);
		memcpy(cipherByte + i, enc_reg, 4);
	}
}

void CFB_dec(unsigned char* cipherByte, unsigned char* plainByte, unsigned char* ivByte, int len) {
	unsigned char enc_reg[16];
	unsigned char tmpIv[16];

	memcpy(tmpIv, ivByte, 16);
	encrypt(tmpIv, enc_reg);
	XOR(enc_reg, cipherByte, 4);
	memcpy(plainByte, enc_reg, 4);

	for (int i = 4; i < len; i+=4)
	{
		leftShift(tmpIv, 16, 4);
		memcpy(tmpIv + 12, cipherByte + i - 4, 4);
		encrypt(tmpIv, enc_reg);
		XOR(enc_reg, cipherByte + i, 4);
		memcpy(plainByte + i, enc_reg, 4);
	}
}

void CFB_test(char* plainfile, char* cipherfile, char* ivStr) {
	clock_t start, end;
	long fsize;
	char* pbuffer;
	char* cbuffer;
	unsigned char* plainByte;
	unsigned char* cipherByte;
	unsigned char ivByte[16];
	size_t result;
	FILE* fp;

	fp = fopen(plainfile, "rb");
	if (fp == NULL) {
		printf("open error\n");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	pbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	cbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	fread(pbuffer, 1, fsize, fp);
	pbuffer[fsize] = '\x00';
	cbuffer[fsize] = '\x00';
	fclose(fp);
	plainByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));
	cipherByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));

	hexToByte(ivStr, ivByte, 32);
	hexToByte(pbuffer, plainByte, fsize);

	start = clock();
	CFB_enc(plainByte, cipherByte, ivByte, fsize / 2);
	end = clock();
	byteToHex(cipherByte, cbuffer, fsize / 2);
	cout << "[*] 加密结果：" << cbuffer << endl;

	memset(plainByte, 0, fsize / 2);
	memset(pbuffer, 0, fsize);

	CFB_dec(cipherByte, plainByte, ivByte, fsize / 2);
	byteToHex(plainByte, pbuffer, fsize / 2);
	cout << "[*] 解密结果：" << pbuffer << endl;
	cout << "[+] Running time: " << ((double)end - start) / 1000 << "s\n";
}

void OFB_enc(unsigned char* plainByte, unsigned char* cipherByte, unsigned char* ivByte, int len) {
	unsigned char enc_reg[16];
	unsigned char tmpIv[16];
	unsigned char leftmost[4];

	memcpy(tmpIv, ivByte, 16);
	encrypt(tmpIv, enc_reg);
	memcpy(leftmost, enc_reg, 4);
	XOR(enc_reg, plainByte, 4);
	memcpy(cipherByte, enc_reg, 4);

	for (int i = 4; i < len; i+=4)
	{
		leftShift(tmpIv, 16, 4);
		memcpy(tmpIv + 12, leftmost, 4);
		encrypt(tmpIv, enc_reg);
		memcpy(leftmost, enc_reg, 4);
		XOR(enc_reg, plainByte + i, 4);
		memcpy(cipherByte + i, enc_reg, 4);
	}
}

void OFB_dec(unsigned char* cipherByte, unsigned char* plainByte, unsigned char* ivByte, int len) {
	unsigned char enc_reg[16];
	unsigned char tmpIv[16];
	unsigned char leftmost[4];

	memcpy(tmpIv, ivByte, 16);
	encrypt(tmpIv, enc_reg);
	memcpy(leftmost, enc_reg, 4);
	XOR(enc_reg, cipherByte, 4);
	memcpy(plainByte, enc_reg, 4);

	for (int i = 4; i < len; i+=4)
	{
		leftShift(tmpIv, 16, 4);
		memcpy(tmpIv + 12, leftmost, 4);
		encrypt(tmpIv, enc_reg);
		memcpy(leftmost, enc_reg, 4);
		XOR(enc_reg, cipherByte + i, 4);
		memcpy(plainByte + i, enc_reg, 4);
	}
}

void OFB_test(char* plainfile, char* cipherfile, char* ivStr) {
	clock_t start, end;
	long fsize;
	char* pbuffer;
	char* cbuffer;
	unsigned char* plainByte;
	unsigned char* cipherByte;
	unsigned char ivByte[16];
	size_t result;
	FILE* fp;

	fp = fopen(plainfile, "rb");
	if (fp == NULL) {
		printf("open error\n");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	pbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	cbuffer = (char*)malloc(sizeof(char) * fsize + 1);
	fread(pbuffer, 1, fsize, fp);
	pbuffer[fsize] = '\x00';
	cbuffer[fsize] = '\x00';
	fclose(fp);
	plainByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));
	cipherByte = (unsigned char*)malloc(sizeof(unsigned char) * (fsize / 2));

	hexToByte(ivStr, ivByte, 32);
	hexToByte(pbuffer, plainByte, fsize);

	start = clock();
	OFB_enc(plainByte, cipherByte, ivByte, fsize / 2);
	end = clock();
	byteToHex(cipherByte, cbuffer, fsize / 2);
	cout << "[*] 加密结果：" << cbuffer << endl;

	memset(plainByte, 0, fsize / 2);
	memset(pbuffer, 0, fsize);

	OFB_dec(cipherByte, plainByte, ivByte, fsize / 2);
	byteToHex(plainByte, pbuffer, fsize / 2);
	cout << "[*] 解密结果：" << pbuffer << endl;
	cout << "[+] Running time: " << ((double)end - start) / 1000 << "s\n";
}