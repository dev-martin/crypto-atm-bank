/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "../util/list.h"


// for encrypt/decrypt
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
    // TODO add more, as needed
    unsigned char * key;
    uint64_t p, g;
	
} Bank;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, unsigned char  *data, size_t data_len);
ssize_t bank_recv(Bank *bank, unsigned char  *data, size_t max_data_len);
void bank_process_local_command (Bank  *bank,  List *clients,  char *command, size_t len);
void bank_process_remote_command(Bank *bank, List *clients, unsigned char  *command, size_t len);
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

/*********** LOCAL COMMANDS ************/


/* First, check it file.bank is correct and can be open, ./bank was called correctly, etc... 
* If so return 0 and show prompt and continue program. Else, return 64 and show err_msg */

int check_file(Bank *bank, char *filename);


/* Check command is a proper and correct command. If it is not, show err_msg and go back to ask for
 * new command. Else, continue proccessing the command.
 * Also, it maps a command to a number [1,2,3] so we can do a switch case op on it afterwards
 * Command's extra arg will be returned in *arg1, *arg2, *arg3, for example create-user <name> <pin> <balance>
 * It returns -1 if it fails, or number if it succeeds.*/

int check_command(void *command, char *arg1, char *arg2, char *arg3); 


/* Check user-name provided. If its a valid username continue. Else, return and print err_msg
 * Return 0 if its good, return -1 if it is bad.*/

int check_user_name_local(char *user_name);


/* Check pin provided. If its a valid pin continue. Else, return and print err_msg
 * Return 0 if its good, return -1 if it is bad.*/

int check_pin(char *pin);


/* Now, we have sanitized input. Updates users global list following bank.md specs.
 * Creates the corresponding files.
 * Upon succes, returns 0. Else, returns -1 and print err_msgs*/

int create_user(List *clients, char *user_name, char *pin, int balance);


/* Check amt is a valid amt (See atm.md). If it is a valid amount return amount, 
 * else return -1.*/

int check_amt(long amt); 


/* Now, process command following band.md specs. 
 * Upon succes return 0. Else, retunr -1 and print error_msgs.*/

int deposit(List *clients, char *user_name, int balance);


/* Now, process command following band.md specs. 
* Upon succes return 0. Else, retunr -1 and print error_msgs.*/

int balance_local(List *clients, char *user_name);


/*********** REMOTE COMMANDS ************/

/* Now process request, check if that withdraw is feasable cheking on out users list for that user.
* 1. Check if user exists. 2. Check if user's balance - amt > 0.
* 3. If so, user's balance = user's balance - amt. 4. Else, dont change it.
* Upon succes return 0 and answer back to atm with the information,
* Else, return -1 and answer back with an error_code.*/

int withdraw_remote(Bank *bank, List *clients, char *user_name, int amount); 


/* Now process request, check if that balance op is feasable by cheking on out users list for that user.
 * 1. Check if user exists. 2. If so, send balance.
 * Upon succes return 0 and answer back to atm with the information,
 * Else, return -1 and answer back with an error_code.*/

int balance_remote(Bank *bank,List *clients, char *user_name);


/* ATM contacts bank to see if the given username exists in database(users list). 
 * We answer whether it is correct or no. Upon succes return 0, else return -1. */

int check_user_name_remote(Bank *bank,List *clients, char *user_name); 


/* ATM contacts bank to see if given PIN is the correct one. Bank checks on users list if the given
 * PIN matches the pin for that user_name. Answers back to ATM accordingly.
 * Returns 0 on succes, else returns -1. */

int check_pin_remote(Bank *bank,List *clients, char *user_name, char*pin);


/* Check command is a proper and correct command. If it is not, show err_msg and go back to ask for
 * new command. Else, continue proccessing the command.
 * Also, it maps a command to a number [1,2,3,4] so we can do a switch case op on it afterwards
 * Command's extra arg will be returned in *arg1,*arg2 for example withdraw [user_name] <amt>
 * It returns -1 if it fails, or number if it succeeds.*/

int check_command_remote(Bank *bank, unsigned char *command, char *username, char *pin, long *amt, size_t len);



/* Sets bank init state for diffie hellman protocol and starts playing diffie hellman protocol. */

int diffie_hellman(Bank *bank);


/* Encrypts given plaintext using key generated by diffie hellman protocol with bank using AES-256 Encryption with streaming type: CBC*/

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);



/* Reverses encryption with key generated in diffie hellman protocol of given ciphertext encrypted with AES-256 Encryption and streaming type: CBC*/

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);



/* Hashes given message using SHA256. */

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);



/* Converts hash binary data into string representation. */

void string_digest(unsigned char * hash, char * output);



#endif


