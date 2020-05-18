#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <endian.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


#define MAX_NAME_LEN 250
#define MAX_ENCRYPT 1000

unsigned char *iv = (unsigned char *) "alexhaimartindav";

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL){
			handleErrors();
		return;
	}

		if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){
			handleErrors();
		return;
	}

		if(1 != EVP_DigestUpdate(mdctx, message, message_len)){
			handleErrors();
		return;
	}

		if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL){
			handleErrors();
		return;
	}

		if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)){
			handleErrors();
		return;
	}

	EVP_MD_CTX_destroy(mdctx);
}

void string_digest(unsigned char * hash, char * output){
	int j = 0;
	char subhash[3];
	for (int i = 0; i < 32; i++){
		sprintf(subhash, "%02x", hash[i]);
        output[j] = subhash[0];
		output[j+1] = subhash[1];
		j += 2;
    }
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed
	bank->key = (unsigned char *) malloc(sizeof(unsigned char) * 33);

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
		free(bank->key);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, unsigned char  *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, unsigned char  *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

int check_file(Bank *bank, char *filename)
{
	char line[10000];
	int currline = 0;

  	FILE *fd = fopen(filename, "r");
  	if(fd == NULL){
    	printf("Error opening bank initialization file\n");
    	return 64;
    } else {
		while (fgets(line, 10000, fd) != NULL){
			if (currline == 0){
				bank->p = strtoull(line, NULL, 10);
			} else if (currline == 1){
				bank->g = strtoull(line, NULL, 10);
			} else if (currline == 2){
				strncpy((char *)bank->key, line, strlen(line)+1);
			}
			currline += 1;
		}
		fclose(fd);
		return 0;
 	}
}

int check_command(void *command, char *arg1, char *arg2, char *arg3)
{
	char *tok, comm[251] = {'\0'};
	char temp_arg1[251] = {'\0'}, temp_arg2[251] = {'\0'}, temp_arg3[251] = {'\0'};
	char *error1 = "Usage:\tcreate-user <user-name> <pin> <balance>\n";
	char *error2 = "Usage:\tdeposit <user-name> <amt>\n";
	char *error3 = "Usage:\tbalance <user-name>\n";
	char error[251] = {'\0'};
	int args = 0;
  	int flags = 0;
	regex_t regex;

	tok = strtok(command, " ");

	bzero(arg1, 251);
	bzero(arg2, 251);
	bzero(arg3, 251);

	while(tok != NULL){
		args++;
		if (args == 1){
			strncpy(comm, tok, strlen(tok));
			if (!strcmp(comm, "create-user")){
				strncpy(error, error1, strlen(error1));

			} else if (!strcmp(comm, "deposit")) {
				strncpy(error, error2, strlen(error2));

			} else if (!strcmp(comm, "balance")) {
				strncpy(error, error3, strlen(error3));

			} else {
				printf("Invalid command\n");
				return -1;
			}
		} else {
			if (args > 4 || strlen(tok) > 250){
				printf("%s", error);
				return -1;
			}
			if (args == 2) {
				strncpy(temp_arg1, tok, strlen(tok));
			} else if (args == 3){
				strncpy(temp_arg2, tok, strlen(tok));
			} else {
				strncpy(temp_arg3, tok, strlen(tok));
			}
		}
		tok = strtok(NULL, " ");
	}

	if (!strcmp(comm, "create-user")){ 

		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", flags);

		if (!strcmp(temp_arg1, "") || regexec(&regex, temp_arg1, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}
		regcomp(&regex, "^[0-9][0-9][0-9][0-9]$", 0);
		if (!strcmp(temp_arg2, "") || regexec(&regex, temp_arg2, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}
		regcomp(&regex, "^[0-9][0-9]*$", 0);
		if (!strcmp(temp_arg3, "") || regexec(&regex, temp_arg3, 0, NULL, 0) ){
			printf("%s", error);
			return -1;
		}
		regfree(&regex);

		strncpy(arg1, temp_arg1, strlen(temp_arg1));
		strncpy(arg2, temp_arg2, strlen(temp_arg2));
		strncpy(arg3, temp_arg3, strlen(temp_arg3));
		return 1;

	} else if (!strcmp(comm, "deposit")){

		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (!strcmp(temp_arg1, "") || regexec(&regex, temp_arg1, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}
		regcomp(&regex, "^[0-9][0-9]*$", 0);
		if (!strcmp(temp_arg2, "") || regexec(&regex, temp_arg2, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}
		if (strcmp(temp_arg3, "") != 0){
			printf("%s", error);
			return -1;
		}
		regfree(&regex);

		strncpy(arg1, temp_arg1, strlen(temp_arg1));
		strncpy(arg2, temp_arg2, strlen(temp_arg2));
		return 2;

	} else {

		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (!strcmp(temp_arg1, "") || regexec(&regex, temp_arg1, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}

		if (strcmp(temp_arg2, "") != 0 ||
		    strcmp(temp_arg3, "") != 0){
			printf("%s", error);
			return -1;
		}
		regfree(&regex);

		strncpy(arg1, temp_arg1, strlen(temp_arg1));
		return 3;
	}
}

int check_user_name_local(char *user_name) 
{
	regex_t regex;
    int ret, success = 0;

    ret = regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        exit(-1);
    }

    ret = regexec(&regex, user_name, 0, NULL, 0);

    if (!ret && (strlen(user_name) <= MAX_NAME_LEN)) {
		    success = 1;
    }

    regfree(&regex);
	if (success == 1) return 0;
	else return 1;

}

int check_pin(char *pin)
{
	int error = 0;

	for( int i = 0 ; i < strlen(pin); i++ ){
		if(pin[i] > 57 || pin[i] < 48) 
		{
			error = -1;
			return error;
		}
	}
	return error;
}

int create_user(List *clients, char *user_name, char *pin, int balance) 
{
	char *fname = (char *)malloc(sizeof(char *) * (strlen(user_name) + 1 + 5));
	bzero(fname, strlen(user_name) + 1 + 5);

	strncat(fname,user_name,strlen(user_name)+1);
	strncat(fname,".card", 6);
	fname[strlen(user_name) + 1 + 5 + 1] = '\0';

	if( access( fname, F_OK ) == -1 ){
		if(list_find(clients, user_name) == NULL ){

			char path[300] = {};

		 	strncat(path, user_name, strlen(user_name) + 1);
		  	strncat(path, ".card", 6);
		  	path[strlen(user_name) + 1 + 5 + 1] = '\0';

			int fd1 = open(path, O_WRONLY | O_CREAT);
			if(fd1 == -1){
				printf("Error creating card file for user %s\n", user_name);
				list_del(clients, user_name);
				return -1;
			}

			/* Write SHA256(username + SHA256(pin) + timestamp)*/
			unsigned int hashlen = 0;
			unsigned char * hashedpin;
			char stored_hash[65] = {'\0'};
			digest_message((unsigned char*)pin, 4, &hashedpin, &hashlen);
			string_digest(hashedpin, stored_hash);

			int buff_len = strlen(user_name) + 32 + sizeof(time_t);
			unsigned char buffer[buff_len];
			time_t timestamp = time(NULL);

			memcpy(&buffer[0],user_name,strlen(user_name));
			memcpy(&buffer[strlen(user_name)],hashedpin,32);
			memcpy(&buffer[strlen(user_name) + 32],&timestamp,sizeof(time_t));

			unsigned char *card_content;
			unsigned int card_content_len = 0;
			digest_message(buffer,buff_len,&card_content,&card_content_len);

			char card_content_string[65] = {'\0'};
			string_digest(card_content, card_content_string);

			list_add(clients, user_name, &balance, stored_hash, card_content_string);


			write(fd1, card_content_string, 65);
			close(fd1);

			printf("Created user %s\n", user_name);
			
		} else {
			printf("Error:\tuser %s already exists\n", user_name);
			return -1;
		}
	}
	else{
		if(list_find(clients, user_name) != NULL )
			printf("Error:\tuser %s already exists\n", user_name);
		else
			printf("Error creating card file for user %s\n", user_name);

		return -1;
	}

	return 0;

}

int check_amt(long amt)
{
	if (amt < 0 || amt > INT_MAX){
		printf("Too rich for this program\n");
		return -1;
	}
	return amt;
}

int overflow(int a, int b) {
	int result = a + b;
     if(a > 0 && b > 0 && result < 0)
         return -1;
     if(a < 0 && b < 0 && result > 0)
         return -1;
     return 0;
}

int deposit(List *clients, char *user_name, int balance) 
{
	ListElem *client = list_find(clients, user_name);
	if(client == NULL) {
		printf("No such user\n");
		return -1;
	}

	int curr_balance = client->balance;
	if (overflow(curr_balance, balance) == -1) {
		printf("Too rich for this program\n");
	} else {
		client->balance += balance; 
		printf("$%d added to %s's account\n", balance, user_name);

	}
	return 0;
}

int balance_local(List *clients, char *user_name)
{
	ListElem *client = list_find(clients, user_name);

	if(client != NULL){
		printf("$%d\n", client->balance);
	} else {
		printf("No such user\n");
    	return -1;
	}
	return 0;
}

int withdraw_remote(Bank *bank, List *clients, char *user_name, int amount) 
{
	ListElem *client = list_find(clients, user_name);
	int error = 0;
	int payload_size =  4 ;

	uint32_t  sufficient = 1;
	uint32_t  net_sufficient;
	unsigned char payload[payload_size];

	if( client == NULL ){
		error = -1;
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return error;
	}
	else{

		if( client->balance - amount >= 0)
		{
			client->balance = client->balance - amount;

			bzero(payload,payload_size);

			sufficient = 1;
			net_sufficient  = htobe32(sufficient);

			memcpy(&payload[0], &net_sufficient,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send(bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		} else {
			bzero(payload,payload_size);

			sufficient = 0;
			net_sufficient  = htobe32(sufficient);

			memcpy(&payload[0], &net_sufficient,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;
			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send(bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

			error = -1;
			return error;
		}

	}

	return error;
}

int balance_remote(Bank *bank, List *clients, char *user_name)
{
	int payload_size =  4 ;
	uint32_t  balance  = 1;
	uint32_t  net_balance ;
	unsigned char payload[payload_size];

	ListElem *client = list_find(clients, user_name);
	if (client != NULL){
			bzero(payload,payload_size);

			balance  = client->balance;
			net_balance   = htobe32(balance );

			memcpy(&payload[0], &net_balance ,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send( bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

			return 0;
	} else {
		printf("No such user\n");
		return -1;
	}
}

int check_user_name_remote(Bank *bank,List *clients, char *user_name)
{
	int payload_size =  4 ;
	uint32_t  valid  = 1;
	uint32_t  net_valid ;
	unsigned char payload[payload_size];
	int error = 0;

	unsigned char encrypted_payload[100];
	int encrypted_payload_len;

	ListElem *client = list_find(clients, user_name);
  	if(client == NULL){

			bzero(payload,payload_size);

			valid  = 0;
			net_valid   = htobe32(valid );

			memcpy(&payload[0], &net_valid ,4);

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);
			
			if(bank_send(bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

			error = -1;
			return error;
  	} else {
			bzero(payload,payload_size);

			valid = 1;
			net_valid = htobe32(valid);

			memcpy(&payload[0], &net_valid ,4);

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if(bank_send(bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

			return 0;
  	}
}

int check_pin_remote(Bank *bank,List *clients, char *user_name, char*pin)
{
	int host_correct_pin = 0;
	int net_correct_pin = 0;
	int payload_size = 4;
	unsigned char payload[payload_size];
	ListElem *client = list_find(clients, user_name);

	if(client != NULL){

		if(strcmp(pin, client->pin) == 0){
			/* Check user's card is a valid card. */
			char *fname = (char *)malloc(sizeof(char *) * (strlen(user_name) + 1 + 5));
			bzero(fname, strlen(user_name) + 1 + 5);
		
			strncat(fname,user_name,strlen(user_name)+1);
			strncat(fname,".card", 6);
			fname[strlen(user_name) + 1 + 5 + 1] = '\0';

		  	FILE *card = fopen(fname, "r");
		  	char line[65];
		  	if (fgets(line, 65, card) != NULL){
		  		if(strcmp(line,client->card_content) == 0)
		  			host_correct_pin = 1;	
		  		else
		  			host_correct_pin = 0;
		  	}	

			fclose(card);
 			
			/*************/

			bzero(payload,payload_size);

			net_correct_pin  = htobe32(host_correct_pin);

			memcpy(&payload[0], &net_correct_pin,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send( bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		    return 0;
		} else {
			bzero(payload,payload_size);

			host_correct_pin = 0;
			net_correct_pin  = htobe32(host_correct_pin);

			memcpy(&payload[0], &net_correct_pin,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send( bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		    return -1;
		}
	} else {
			bzero(payload,payload_size);

			host_correct_pin = 0;
			net_correct_pin  = htobe32(host_correct_pin);

			memcpy(&payload[0], &net_correct_pin,4);

			unsigned char encrypted_payload[MAX_ENCRYPT];
			int encrypted_payload_len;

			encrypted_payload_len = encrypt(payload, payload_size, bank->key, iv, encrypted_payload);

			if( bank_send( bank, encrypted_payload, encrypted_payload_len) < 0)
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		    return -1;
	}
}

typedef uint64_t ull;

ull mod_exp(ull a, ull b, ull m)
{
    ull result = 1;
    while (b)
    {
        if (b & 1)
            result = result * a % m;
        b >>= 1;
        a = (unsigned long)a * a % m;
    }
    return result;
}

int diffie_hellman(Bank *bank)
{	
	unsigned char  buffer[8];
	bzero(buffer,8);
	int recvd = 0;
	if ( (recvd = bank_recv(bank, buffer, 8)) < 0 ){
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return -1;
	}

	ull net_ga, host_ga;
	memcpy(&net_ga, &buffer[0], 8); host_ga = be64toh(net_ga);

	srand(time(NULL));

	ull host_b = (rand() % ((bank->p)-2)) + 1;

	ull host_gb = mod_exp(bank->g, host_b, bank->p), net_gb;


	int payload_size =  8;
    unsigned char gb_payload[payload_size];	
	bzero(gb_payload, payload_size);	
	
	net_gb = htobe64(host_gb);	

	memcpy(&gb_payload[0], &net_gb, payload_size);
	
	if( bank_send(bank, gb_payload, payload_size) < 0){
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return -1;
	}
	
	ull key = mod_exp(host_ga, host_b, bank->p);

	char char_key[20] = {'\0'};
	sprintf(char_key, "%lu", key);
	for (int i = 0; i < strlen(char_key); i++){
		bank->key[i] = char_key[i];
	}
	return 0;
}

int check_command_remote(Bank *bank, unsigned char *command, char *username, char *pin, long *amt, size_t len)
{
	uint32_t  net_command_len,net_arg1_len,net_arg2_len;
	uint32_t  host_command_len,host_arg1_len,host_arg2_len;

	memcpy(&net_command_len,&command[0],4);
	host_command_len = be32toh(net_command_len);

	char *comm = (char *)malloc(sizeof(char*) * host_command_len);
	bzero(comm, host_command_len);	
	memcpy(&comm[0],&command[4],host_command_len);

	memcpy(&net_arg1_len,&command[4+host_command_len],4);
	host_arg1_len = be32toh(net_arg1_len);

	memcpy(&username[0],&command[4+host_command_len+4],host_arg1_len);

	if( len - 4 - host_command_len - 4 - host_arg1_len > 0){
		memcpy(&net_arg2_len,&command[4+host_command_len+4+host_arg1_len],4);
		host_arg2_len = be32toh(net_arg2_len);
		
		if(strcmp(comm,"check-pin-remote") == 0){
			memcpy(&pin[0],&command[4+host_command_len+4+host_arg1_len+4],host_arg2_len);
		}
		else if(strcmp(comm,"withdraw-remote") == 0){
			uint32_t net_amt;
			memcpy(&net_amt,&command[4+host_command_len+4+host_arg1_len+4],host_arg2_len);
			*amt = be32toh(net_amt);
		}
	}
	else{
		host_arg2_len = 0;
	}

	if( host_command_len > 50 || host_arg1_len > 250 || host_arg2_len > 250)
		return -1;

	char empty[251];
	bzero(empty,251);
	regex_t regex;

	if (!strcmp(comm, "balance-remote")){ 

  		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (regexec(&regex, username, 0, NULL, 0) && strlen(username) > 250){
			return -1;
		}
		regfree(&regex);

		return 1;

	} else if (!strcmp(comm, "withdraw-remote")){

  		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (regexec(&regex, username, 0, NULL, 0) && strlen(username) > 250){
			return -1;
		}
		regcomp(&regex, "^[0-9][0-9]*$", 0);
		if (regexec(&regex, pin, 0, NULL, 0) && strlen(pin) > 10){
			return -1;
		}
		if (*amt < 0 || *amt > 2147483648){ 
			return -1;
		}
		regfree(&regex);

		return 2;

	} else if (!strcmp(comm, "check-username-remote")){

  		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (regexec(&regex, username, 0, NULL, 0) && strlen(username) > 250){
			return -1;
		}
		regfree(&regex);

		return 3;
	} else if (!strcmp(comm, "check-pin-remote")){ 
  		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (regexec(&regex, username, 0, NULL, 0) && strlen(username) > 250){
			return -1;
		}
		regfree(&regex);
		return 4;

	} else if (!strcmp(comm, "diffie-hellman")){ 
		return 5;

	}else {
		printf("Recieved invalid remote command\n");
	}
	return -1;
}

void bank_process_local_command (Bank  *bank,  List *clients,  char  *command, size_t len)
{
	char *arg1  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	char *arg2  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	char *arg3  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	long int amt ;
	int cmd = 0, balance = -1;
	if( (cmd = check_command(command, arg1, arg2, arg3)) <  0)
		return;
	switch(cmd)
	{
		case 1:
			if( check_user_name_local(arg1)  != 0 )
				return;

			if( check_pin(arg2)  != 0 )
				return;

			amt = strtol(arg3, NULL, 10);
			if( (balance = check_amt(amt)) < 0)
				return;

			if( create_user(clients, arg1, arg2, balance)  != 0 )
				return;

			break;

		case 2:
			if( check_user_name_local(arg1)  != 0 )
				return;

			amt = strtol(arg2, NULL, 10);
			if( (balance = check_amt(amt)) < 0)
				return;

			if( deposit(clients, arg1, balance) !=  0)
				return;

			break;

		case 3:

			if( check_user_name_local(arg1)  != 0 )
				return;

			if( balance_local(clients,arg1) !=  0)
				return;

			break;

		default:
			break;


	}

}

void bank_process_remote_command(Bank *bank, List *clients,  unsigned char *command, size_t len)
{
	char *username  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	char *pin  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	long amt;
	bzero(username,MAX_NAME_LEN + 1);
	bzero(pin,MAX_NAME_LEN + 1);

	int cmd = 0;
	if( (cmd = check_command_remote(bank, command, username, pin, &amt, len)) <  0)
		return;
	switch(cmd)
	{
		case 1:
			if( check_user_name_local(username)  != 0 )
				return;

			if( balance_remote(bank, clients, username) !=  0)
				return;
			break;

		case 2:
			if( check_user_name_local(username)  != 0 )
				return;

			if( (amt = check_amt(amt)) < 0)
				return;

			if( withdraw_remote(bank, clients, username,amt) !=  0)
				return;
			break;

		case 3:
			if( check_user_name_remote(bank,clients, username) !=  0)
				return;
			break;

		case 4:

			if( check_pin_remote(bank, clients, username,pin) !=  0)
				return;
			break;

		case 5:
			if (diffie_hellman(bank) != 0){
				printf("Unable to establish new key.\n");
				return;
			}
			break;

		default:
			break;
	}
}
