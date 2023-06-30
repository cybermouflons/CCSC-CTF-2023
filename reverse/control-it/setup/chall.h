#ifndef CHALL_H_
#define CHALL_H_

#define INPUT_DATA_SIZE 33
#define NUMBER_OF_FLOWS 5
#define	SIZE_OF_FLOW 8
#define XOR_KEY_LEN 16
#define SECONDS 60
#define WELCOME_MESSAGE "Control the flow and the flag will appear\n"
#define SUCCESS_MESSAGE "Good job, you found the flag!\n"
#define FAILURE_MESSAGE "You failed to control the flow\n"
#define INVALID_FLOW "Flow not found\n"

typedef int (*flow)(void*);

typedef struct {
	unsigned int position;
	flow* flows;
	unsigned char *inputData;
} Controller;

int initialize(void*);

int executeFlow1(void*);

int executeFlow2(void*);

int executeFlow3(void*);

int executeFlow4(void*);

int executeFlow5(void*);

void cleanup(void*);

void chkUpdate(unsigned short* chk, unsigned char c, unsigned int position);

#endif
