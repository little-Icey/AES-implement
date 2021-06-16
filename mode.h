#pragma once
#ifndef _MODE_H__
#define _MODE_H__

void ECB_test(char* plainfile, char* cipherfile);

void CBC_test(char* plainfile, char* cipherfile, char* ivStr);

void CFB_test(char* plainfile, char* cipherfile, char* ivStr);

void OFB_test(char* plainfile, char* cipherfile, char* ivStr);
#endif