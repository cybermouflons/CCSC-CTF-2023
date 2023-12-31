#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "chall.h"

const unsigned char xorKey[] = {
	0xac, 0xab, 0xe6, 0xae, 0xa4, 0x20, 0x58, 0xf3, 0x37, 0xad, 0xdc, 0x2a,
	0xc8, 0x45, 0x85, 0x34
};

const unsigned char xorCipher[] = {
	0xef, 0xe8, 0xb5, 0xed, 0xdf, 0x47, 0x68, 0xac, 0x60, 0x9c, 0xa8, 0x42,
	0x97, 0x11, 0xed, 0x07
};

const unsigned char mapping[] = {
  0xd7, 0xf2, 0xd4, 0x15, 0xea, 0x51, 0xab, 0x04, 0xa7, 0x42, 0xe8, 0x0e,
  0x0b, 0x48, 0x8b, 0x27, 0x9b, 0x99, 0x3a, 0xdd, 0x5f, 0xda, 0x75, 0x21,
  0x94, 0xb5, 0xa8, 0x76, 0x59, 0x09, 0x3e, 0x1f, 0x87, 0x0d, 0xef, 0x37,
  0xa4, 0xc1, 0x78, 0xa9, 0x28, 0x57, 0x38, 0xd5, 0xaf, 0x7b, 0x85, 0x9f,
  0xb8, 0x8d, 0x96, 0x26, 0x40, 0x50, 0xa0, 0x63, 0x4d, 0xe3, 0x72, 0x61,
  0xe0, 0x97, 0xbd, 0x66, 0x06, 0x1a, 0xe5, 0xe4, 0x58, 0x2b, 0x1b, 0xd0,
  0x9a, 0x56, 0xf5, 0xe1, 0xb1, 0x7d, 0xe9, 0x6b, 0xfa, 0xb7, 0x3b, 0x88,
  0xd1, 0x17, 0x34, 0x14, 0x84, 0x24, 0x11, 0xfd, 0x64, 0xf1, 0x73, 0x8f,
  0xac, 0x39, 0x68, 0x20, 0xeb, 0xad, 0xe2, 0x7e, 0x1d, 0x77, 0x07, 0x08,
  0x8e, 0xcd, 0x82, 0x7c, 0xae, 0x44, 0x45, 0x41, 0x8a, 0x25, 0x2a, 0x6e,
  0x31, 0x9c, 0x29, 0x22, 0xd9, 0x30, 0x71, 0x1c, 0x2c, 0xa5, 0x02, 0xdf,
  0xc2, 0x5c, 0xba, 0x6a, 0xb6, 0x8c, 0xee, 0xfc, 0xb2, 0x18, 0x7f, 0xf8,
  0xc4, 0x4c, 0x9d, 0x5e, 0x62, 0x00, 0x03, 0xa3, 0xb0, 0xc8, 0xc5, 0xa6,
  0x05, 0xaa, 0xdb, 0xbe, 0xd6, 0x01, 0x93, 0x4e, 0x70, 0xfb, 0xcf, 0x10,
  0x3d, 0x4b, 0xde, 0x2e, 0x36, 0x5d, 0x35, 0x19, 0x65, 0x55, 0x6d, 0xfe,
  0x5b, 0x86, 0xa1, 0xc7, 0xf6, 0x32, 0xbc, 0x91, 0xc0, 0x95, 0xa2, 0x12,
  0x9e, 0xca, 0xf7, 0xdc, 0x0f, 0x33, 0xec, 0x90, 0x5a, 0xbb, 0x60, 0x81,
  0x0a, 0x23, 0xb9, 0x52, 0xd3, 0x2f, 0x3f, 0xcc, 0x1e, 0x89, 0x98, 0xb3,
  0xe6, 0xd8, 0xbf, 0x13, 0x54, 0x49, 0x4a, 0x6f, 0xce, 0x74, 0x53, 0xc6,
  0x7a, 0xf3, 0xcb, 0xed, 0x67, 0x0c, 0x2d, 0x46, 0x69, 0x83, 0x4f, 0xf4,
  0x92, 0xf0, 0x79, 0x80, 0xc3, 0x6c, 0xe7, 0x47, 0x16, 0x3c, 0x43, 0xc9,
  0xb4, 0xf9, 0xd2
};

const unsigned short chks[] = { 0x296, 0x16a, 0x38a, 0x3ee,
	0xc8, 0xbc, 0xc4, 0x1e
};

int executeFlow1(void* arg){
	Controller* controller = arg;
	unsigned char* inputData = (unsigned char*) controller->inputData;
	if (fgets(inputData, INPUT_DATA_SIZE, stdin) == NULL){
		return 4;
	}
	else{
		if (strlen(inputData) != 32){
			return 4;
		}
	}
	return 1;
}

int executeFlow2(void* arg){
	Controller* controller = arg;
	unsigned char* inputData = (unsigned char*) controller->inputData;
	unsigned char cipher = 0x0;
	for (int i=0; i < XOR_KEY_LEN ; i++){
		cipher = inputData[i] ^ xorKey[i];
		if (cipher != xorCipher[i]){
			return 4;
		}
	}
	return 2;
}

int executeFlow3(void* arg){
	Controller* controller = arg;
	unsigned short chk = 0;
	unsigned char* inputData = (unsigned char*) controller->inputData;
	unsigned int position = 0;
	unsigned int counter = 0;

	/*checking until the 32th bytes*/
	/*31th position is the last byte*/
	for (int i = 16; i < INPUT_DATA_SIZE - 1 ; i++){
		position = (i % 2) == 0 ? 1: 2;
		if ( position == 0){
			chk = 0xcafe;
		}
		chkUpdate(&chk, inputData[i], position);
		if ( (i % 2) == 1){
			if (chks[counter] != chk){
				return 4;
			}
			counter += 1;
		}
	}
	return 3;
}

int executeFlow4(void* arg){
	Controller* controller = arg;
	unsigned char* inputData = (unsigned char*) controller->inputData;
	printf("[*]%s", SUCCESS_MESSAGE);
	return 0xff;
}

int executeFlow5(void* arg){
	Controller* controller = arg;
	sleep(SECONDS);
	printf("[*]%s", FAILURE_MESSAGE);
	return 0xff;
}

int initialize(void* arg){
	Controller* controller = arg;
	flow* flows = (flow *) malloc(sizeof(flow) * NUMBER_OF_FLOWS);
	if (flows == NULL){
		return -1;
	}
	char * inputData = (char *) malloc(sizeof(char) * INPUT_DATA_SIZE);
	if (inputData == NULL){
		return -1;
	}
	/*initialize flows*/
	flows[0] = &executeFlow1;
	flows[1] = &executeFlow2;
	flows[2] = &executeFlow3;
	flows[3] = &executeFlow4;
	flows[4] = &executeFlow5;
	controller->position = 0x0;
	controller->flows = flows;
	controller->inputData = inputData;	
	return 0;
}

void cleanup(void* arg){
	Controller* controller = arg;
	free(controller->flows);
	free(controller->inputData);
}

void chkUpdate(unsigned short* chk, unsigned char c, unsigned int position){
	*chk ^= (mapping[c] << position);
}

int main(int argc, char **argv){
	Controller* controller = (Controller*) malloc(sizeof(Controller));
	if (controller == NULL){
		return -1;
	}

	if (!initialize(controller)){
		printf("%s \n",WELCOME_MESSAGE);
		while (controller->position != 0xff){
			switch(controller->position){
				case (132 % 3):
					controller->position = controller->flows[0](controller);
					break;
				case (781 >> 9):
					controller->position = controller->flows[1](controller);
					break;
				case ((6 << 2) % 11):
					controller->position = controller->flows[2](controller);
					break;
				case (120 >> 5):
					controller->position = controller->flows[3](controller);
					break;
				case (1054 % 21):
					controller->position = controller->flows[4](controller);
					break;
				default:
					printf("[*]%s",INVALID_FLOW);
					controller->position = 0xff;
			}
		}
		cleanup(controller);
	}
	else{
		free(controller);
	}
}
