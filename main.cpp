#include<cstdio>
#include<cstdlib>
#include<iostream>
#include<fstream>
#include<cstring>
#include "aes.h"
#include "mode.h"

using namespace std;

typedef struct commandline {
	char* plainfile;
	char* keyfile;
	char* ivfile;
	char* mode;
	char* cipherfile;

}commands;

commandline com;

int main(int argc, char* argv[]) {

	ifstream infile;
	ofstream outfile;

	char keyStr[33] = { '\x00' };
	char ivStr[33] = { '\x00' };
	char plainStr[65] = { '\x00' };
	unsigned char plainByte[32];
	unsigned char plainArray[4][4];
	unsigned char keyByte[16];
	int mode_num = 0;

	for (int i = 1; i < argc; i += 2) {
		if (!strcmp(argv[i], "-p"))
			com.plainfile = argv[i + 1];
		else if (!strcmp(argv[i], "-k"))
			com.keyfile = argv[i + 1];
		else if (!strcmp(argv[i], "-v"))
			com.ivfile = argv[i + 1];
		else if (!strcmp(argv[i], "-m"))
			com.mode = argv[i + 1];
		else if (!strcmp(argv[i], "-c"))
			com.cipherfile = argv[i + 1];
	}

	if (!strcmp(com.mode, "ECB"))
		mode_num = 1;
	else if (!strcmp(com.mode, "CBC"))
		mode_num = 2;
	else if (!strcmp(com.mode, "CFB"))
		mode_num = 3;
	else if (!strcmp(com.mode, "OFB"))
		mode_num = 4;

	infile.open(com.keyfile);
	infile >> keyStr;
	infile.close();

	infile.open(com.ivfile);
	infile >> ivStr;
	infile.close();

	infile.open(com.plainfile);
	infile >> plainStr;
	infile.close();

	cout << "[+] key:" << keyStr << endl;
	cout << "[+] iv:" << ivStr << endl;
	cout << "[+] plain:" << plainStr << endl;

	hexToByte(keyStr, keyByte, 32);
	changeToArray(keyByte, key);
	generateExtendKey(key, extendKey);

	switch (mode_num)
	{
	case 1:
		ECB_test(com.plainfile, com.cipherfile);
		break;
	case 2:
		CBC_test(com.plainfile, com.cipherfile, ivStr);
		break;
	case 3:
		CFB_test(com.plainfile, com.cipherfile, ivStr);
		break;
	case 4:
		OFB_test(com.plainfile, com.cipherfile, ivStr);
		break;
	default:
		break;
	}


	
}

	