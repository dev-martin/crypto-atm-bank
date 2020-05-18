#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <fcntl.h>
#include <regex.h>
#include <time.h>
#include <stdio.h>
#include <termios.h>

#define MAX_NAME_LEN 250
#define MAX_ENCRYPT 1000

void print_hex(unsigned char *text, int len);

unsigned char *iv = (unsigned char *) "alexhaimartindav";

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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
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

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed
	atm->logged_in = NULL;
	atm->key = (unsigned char *)malloc(sizeof(unsigned char) * 33);
	atm->attempts = 0;
	atm->max_attempts = 3;
	atm->to_min = 1;

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
		free(atm->key);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, unsigned char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, unsigned char  *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

int check_file(ATM *atm, char *filename)
{	
	char line[10000];
	int currline = 0;

  	FILE *fd = fopen(filename, "r");
  	if(fd == NULL){
    	printf("Error opening ATM initialization file\n");
    	return 64;
    } else {
		while (fgets(line, 10000, fd) != NULL){
			if (currline == 0){
				atm->p = strtoull(line, NULL, 10);
			} else if (currline == 1){
				atm->g = strtoull(line, NULL, 10);
			} else if (currline == 2){
				strncpy((char *)atm->key, line, strlen(line)+1);
			}
			currline += 1;
		}
		fclose(fd);
		return 0;
 	}
}


int check_command(ATM *atm, char *command, char *input)
{
	char *tok, comm[251] = {'\0'}, arg1[251] = {'\0'};
	char *error1 = "Usage:\tbegin-session <user-name>\n";
	char *error2 = "Usage:\twithdraw <amt>\n";
	char *error3 = "Usage:\tbalance\n";
	char error[251] = {'\0'};
	
	int args = 0;
	regex_t regex;

	tok = strtok(command, " ");

	while(tok != NULL){
		args++;
		if (args == 1){
			strncpy(comm, tok, strlen(tok));
			if (!strcmp(comm, "begin-session")){
				strncpy(error, error1, strlen(error1));
			} else if (!strcmp(comm, "withdraw")){
				strncpy(error, error2, strlen(error2));
			} else if (!strcmp(comm, "balance")){
				strncpy(error, error3, strlen(error3));
			} else if (strcmp(comm, "end-session")){
				printf("Invalid command\n");
				return -1;
			}
		} else {
			if (args > 2 || strlen(tok) > 250){
				printf("%s", error);
				return -1;
			}
			strncpy(arg1, tok, strlen(tok));
		}
		tok = strtok(NULL, " ");
	}

	if (!strcmp(comm, "begin-session")){
  		regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
		if (regexec(&regex, arg1, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}

		regfree(&regex);
		strncpy(input, arg1, strlen(arg1));
		return 1;

	} else if (!strcmp(comm, "withdraw")){
		regcomp(&regex, "^[0-9][0-9]*$", 0);
		if (regexec(&regex, arg1, 0, NULL, 0)){
			printf("%s", error);
			return -1;
		}
		regfree(&regex);
		strncpy(input, arg1, strlen(arg1));
		return 2;

	} else if (!strcmp(comm, "balance")){
		if (strcmp(arg1, "") != 0){
			printf("%s", error);
			return -1;
		}
		return 3;

	} else {
		if (strcmp(arg1, "") != 0){
			return -1;
		}
		return 4;
	}
}

int check_user_name(ATM *atm, char *user_name)
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
    } else {
        printf("Usage:\tbegin-session <user-name>\n");
    }

    regfree(&regex);

	if (success == 1) 
		return 0;
	else 
		return -1;

}

void attempts(ATM *atm){
	atm->attempts += 1;
	if (atm->attempts == atm->max_attempts){
		printf("[!] You have exceeded the amount of permitted PIN attempts.\n");
		printf("Timeout of %d minutes begins now ...\n", atm->to_min);
		sleep(atm->to_min*(60));
		atm->attempts = 0;
		atm->to_min += 5;
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

int diffie_hellman(ATM *atm)
{
	srand(time(NULL));
	
	ull host_a = (rand() % ((atm->p)-2)) + 1;

	ull host_ga = mod_exp(atm->g, host_a, atm->p), net_ga;

	int payload_size =  8;
    unsigned char ga_payload[payload_size];	
	bzero(ga_payload, payload_size);	
	
	net_ga = htobe64(host_ga);	

	memcpy(&ga_payload[0], &net_ga, payload_size);
	
	if( atm_send(atm, ga_payload, payload_size) < 0){
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return -1;
	}	
	
	unsigned char  buffer[8];
	bzero(buffer,8);
	int recvd = 0;
	if ( (recvd = atm_recv(atm, buffer, 8)) <= 0 ){
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return -1;
	}

	ull net_gb, host_gb;
	memcpy(&net_gb, &buffer[0], 8); host_gb = be64toh(net_gb);

	ull key = mod_exp(host_gb, host_a, atm->p);	

	char char_key[20] = {'\0'};
	sprintf(char_key, "%lu", key);
	for (int i = 0; i < strlen(char_key); i++){
		atm->key[i] = char_key[i];
	}
	return 0;
}


int begin_diffie_hellman(ATM *atm){
	char *command = "diffie-hellman";
	int payload_size =  4 + strlen(command) + 1 + 4;
	unsigned char  payload[payload_size];	
	bzero(payload,payload_size);

	uint32_t  command_bytes = strlen(command) + 1; 

	uint32_t  net_command_bytes = htobe32(command_bytes);	
	
	memcpy(&payload[0]                    , &net_command_bytes	,                     4);
	memcpy(&payload[4]                    , command            , strlen(command)   + 1);

	unsigned char encrypted_pl[MAX_ENCRYPT];
	int encrypted_len;
	encrypted_len = encrypt(payload, payload_size, atm->key, iv, encrypted_pl);

	if( atm_send( atm, encrypted_pl, encrypted_len) < 0){
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		return -1;
	}
	
	if (diffie_hellman(atm) != 0){
		printf("Unable to establish new key.\n");
		return -1;
	}
	return 0;
}

int getPIN(char *pin)
{
    static struct termios oldt, newt;
    int i = 0;
    int c, count = 0;

    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    newt.c_lflag &= ~(ECHO);          

    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    while ((c = getchar()) != '\n' && c != EOF){
		if (count < 4){
			pin[i] = c;
			i++;
		}
		count++;
    }
    pin[i] = '\0';

    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	return count;
}

int begin_session(ATM *atm, char *user_name)
{
	int error = 0;

	if(atm->logged_in != NULL)
	{
	 	error = -1;
		printf("A user is already logged in\n");
		return error;
	}

	char *command = "check-username-remote";
	int payload_size =  4 + strlen(command) + 1 + 4 + strlen(user_name) + 1;
    unsigned char  username_payload[payload_size];	
	bzero(username_payload,payload_size);

	uint32_t  command_bytes = strlen(command) + 1; 
	uint32_t  data_bytes    = strlen(user_name) + 1;

	uint32_t  net_command_bytes = htobe32(command_bytes);	
	uint32_t  net_data_bytes = htobe32(data_bytes);	
	
	memcpy(&username_payload[0]                    , &net_command_bytes	,                     4);
	memcpy(&username_payload[4]                    , command            , strlen(command)   + 1);
	memcpy(&username_payload[4 + command_bytes]    , &net_data_bytes    , 					  4);
	memcpy(&username_payload[4 + command_bytes + 4], user_name          , strlen(user_name) + 1);

	unsigned char encrypted_user[MAX_ENCRYPT];
	int encrypted_user_len;
	encrypted_user_len = encrypt(username_payload, payload_size, atm->key, iv, encrypted_user);

	if(atm_send(atm, encrypted_user, encrypted_user_len) < 0)
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");

	int recvd = 0;
	unsigned char user_rcv[MAX_ENCRYPT];

	if ((recvd = atm_recv(atm, user_rcv, 10000)) <= 0 )
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");

	int decrypted_len;
	unsigned char decrypted_text[MAX_ENCRYPT];
	decrypted_len = decrypt(user_rcv, recvd, atm->key, iv, decrypted_text);
	decrypted_text[decrypted_len] = '\0';

	unsigned int net_exists,host_exists;
	memcpy(&net_exists, &decrypted_text[0], decrypted_len);
	
	host_exists = be32toh(net_exists);
	if(host_exists == 1) 
	{
		begin_diffie_hellman(atm);

		char *fname = (char *)malloc(sizeof(char *) * (strlen(user_name) + 1 + 5));
		bzero(fname, strlen(user_name) + 1 + 5);
		
		strncat(fname,user_name,strlen(user_name)+1);
		strncat(fname,".card", 6);
		fname[strlen(user_name) + 1 + 5 + 1] = '\0';

		if( access( fname, F_OK ) != -1 ) {

			printf("PIN?\n");
			char numpin[5];
			int entered_len = getPIN(numpin);
			for (int i = 0; i < entered_len; i++){
				printf("*");
			}
			printf("\n");

			if(entered_len > 4 || entered_len < 4)
			{
				printf("Not authorized\n");
				attempts(atm);
				begin_diffie_hellman(atm);
				error = -1;
				return error;
			}
			
			for( int i = 0 ; i < strlen(numpin); i++ ){
				if(numpin[i] > 57 || numpin[i] < 48) 
				{
					printf("Not authorized\n");
					attempts(atm);
					begin_diffie_hellman(atm);
					error = -1;
					return error;
				}
			}

			unsigned int hashlen = 0;
			char pin[65] = {'\0'};
			unsigned char *pin_buff;
			digest_message((unsigned char *)numpin, 4, &pin_buff, &hashlen);
			string_digest(pin_buff, pin);

			bzero(&command, strlen(command));

			command = "check-pin-remote";

			command_bytes = strlen(command) + 1;
			uint32_t username_bytes = strlen(user_name) + 1;
			uint32_t pin_bytes    = strlen((char *)pin) + 1;

			net_command_bytes = htobe32(command_bytes);	
			uint32_t net_pin_bytes = htobe32(pin_bytes);	
			uint32_t net_username_bytes = htobe32(username_bytes);	

			payload_size =  4 + command_bytes + 4 + username_bytes + 4 + pin_bytes;
			unsigned char  pin_payload [payload_size];
			bzero(pin_payload,payload_size);
			
			memcpy(&pin_payload[0]                                               , &net_command_bytes   ,                      4);
			memcpy(&pin_payload[4]                                               , command              , strlen(command)    + 1);
			memcpy(&pin_payload[4 + command_bytes]                               , &net_username_bytes  ,                      4);
			memcpy(&pin_payload[4 + command_bytes + 4]                           , user_name            , strlen(user_name)  + 1);
			memcpy(&pin_payload[4 + command_bytes + 4 + username_bytes]          , &net_pin_bytes       ,                      4);
			memcpy(&pin_payload[4 + command_bytes + 4 + username_bytes + 4]      , pin                  , strlen((char *)pin)        + 1);

			unsigned char encrypted_pin[MAX_ENCRYPT];
			int encrypted_pin_len;

			encrypted_pin_len = encrypt(pin_payload, payload_size, atm->key, iv, encrypted_pin);

			atm_send( atm, encrypted_pin, encrypted_pin_len);
			
			int recvd = 0;
			unsigned char pin_rcv[MAX_ENCRYPT];

			recvd = 0;
			if ( (recvd = atm_recv(atm, pin_rcv, 10000)) <= 0 )
				printf(" Unexpected error ocurred, sorry.\nTry again.\n");

			int decrypted_len;
			unsigned char decrypted_text[MAX_ENCRYPT];

			decrypted_len = decrypt(pin_rcv, recvd, atm->key, iv, decrypted_text);
			decrypted_text[decrypted_len] = '\0';

			unsigned int net_correct,host_correct;
			memcpy(&net_correct, &decrypted_text[0], decrypted_len);
			
			host_correct = be32toh(net_correct);
			

			if(host_correct == 1)
			{
				atm->logged_in = (char *)malloc(sizeof(char *) * (strlen(user_name) + 1));
				bzero(atm->logged_in, strlen(user_name) + 1);
				strncpy(atm->logged_in, user_name, strlen(user_name));

				printf("Authorized\n");
				atm->attempts = 0;
				return error;
			}else 
			{
				printf("Not authorized\n");
				attempts(atm);
				error = -1;
				return error;
			}
		} else {
			printf("Unable to access %s's card\n",user_name);
			error = -1;
			return error;
		}

	}else if( host_exists == 0)
	{
		printf("No such user.\n");
		error = -1;
		return error;

	}else 
	{
		printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		error = -1;
		return error;
	}

	return error;
}

int check_amt(ATM *atm, char *amount)
{
  regex_t regex;
  int ret_val;
  ret_val = regcomp(&regex, "^[0-9][0-9]*$", 0);

  ret_val = regexec(&regex, amount, 0, NULL, 0);
  regfree(&regex);

  if(!ret_val){
    int temp = 0;
    sscanf(amount, "%d", &temp);
    if(temp >= 0){
      return temp;
    } else {
      printf("Usage:\twithdraw <amt>\n");
      return -1;
    }
  } else {
    printf("Usage:\twithdraw <amt>\n");
    return -1;
  }
}

int withdraw(ATM *atm, int amt)
{
	int recvd;

	if (atm->logged_in == NULL){
		printf("No user logged in\n");
		return -1;
	} else{

		char *command = "withdraw-remote";
		char *user_name = atm->logged_in;
		int payload_size =  4 + strlen(command) + 1 + 4 + strlen(user_name) + 1 + 4 + 4;
		unsigned char  username_payload[payload_size];
		bzero(username_payload,payload_size);

		uint32_t  command_bytes = strlen(command) + 1;
		uint32_t  data_bytes    = strlen(user_name) + 1;
		uint32_t  amt_bytes    = 4;

		uint32_t  net_command_bytes = htobe32(command_bytes);
		uint32_t  net_data_bytes = htobe32(data_bytes);

		uint32_t net_amt = htobe32(amt);
		uint32_t net_amt_bytes = htobe32(amt_bytes);

		memcpy(&username_payload[0]                    , &net_command_bytes	,                     4);
		memcpy(&username_payload[4]                    , command            , strlen(command)   + 1);
		memcpy(&username_payload[4 + command_bytes]    , &net_data_bytes    , 					  4);
		memcpy(&username_payload[4 + command_bytes + 4], user_name          , strlen(user_name) + 1);
		memcpy(&username_payload[4 + command_bytes + 4 + data_bytes],    &net_amt_bytes       ,   4);
		memcpy(&username_payload[4 + command_bytes + 4 + data_bytes + 4],    &net_amt    ,        4);

		unsigned char encrypted_user[MAX_ENCRYPT];
		int encrypted_user_len;

		begin_diffie_hellman(atm);

		encrypted_user_len = encrypt(username_payload, payload_size, atm->key, iv, encrypted_user);

		if( atm_send( atm, encrypted_user, encrypted_user_len) < 0)
			printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		unsigned char amt_rcv[MAX_ENCRYPT];
		recvd = 0;		

		if ((recvd = atm_recv(atm, amt_rcv, 10000)) < 0 )
			printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		int decrypted_len;
		unsigned char decrypted_text[MAX_ENCRYPT];

		decrypted_len = decrypt(amt_rcv, recvd, atm->key, iv, decrypted_text);
		decrypted_text[decrypted_len] = '\0';

		unsigned int net_valid,host_valid;
		memcpy(&net_valid, &decrypted_text[0], decrypted_len);
		
		host_valid = be32toh(net_valid);

		if (host_valid == 1){
			printf("$%d dispensed\n", amt);
			return 0;
		} else {
			printf("Insufficient funds\n");
			return -1;
		}
	}
	return 0;
}

int balance(ATM *atm )
{
	int recvd;
	if(atm->logged_in == NULL){
		printf("No user logged in\n");
		return 1;
	}
	else{

		char *command = "balance-remote";
		char *user_name = atm->logged_in;
		int payload_size =  4 + strlen(command) + 1 + 4 + strlen(user_name) + 1;
		unsigned char  username_payload[payload_size];	
		bzero(username_payload,payload_size);

		uint32_t  command_bytes = strlen(command) + 1; 
		uint32_t  data_bytes    = strlen(user_name) + 1;

		uint32_t  net_command_bytes = htobe32(command_bytes);	
		uint32_t  net_data_bytes = htobe32(data_bytes);	

		memcpy(&username_payload[0]                    , &net_command_bytes	,                     4);
		memcpy(&username_payload[4]                    , command            , strlen(command)   + 1);
		memcpy(&username_payload[4 + command_bytes]    , &net_data_bytes    , 					  4);
		memcpy(&username_payload[4 + command_bytes + 4], user_name          , strlen(user_name) + 1);

		unsigned char encrypted_user[MAX_ENCRYPT];
		int encrypted_user_len;

		begin_diffie_hellman(atm);

		encrypted_user_len = encrypt(username_payload, payload_size, atm->key, iv, encrypted_user);

		if( atm_send( atm, encrypted_user, encrypted_user_len) < 0)
			printf(" Unexpected error ocurred, sorry.\nTry again.\n");
		
		unsigned char amt_rcv[MAX_ENCRYPT];
		recvd = 0;

		if ((recvd = atm_recv(atm, amt_rcv, 10000)) < 0 )
			printf(" Unexpected error ocurred, sorry.\nTry again.\n");

		int decrypted_len;
		unsigned char decrypted_text[MAX_ENCRYPT];

		decrypted_len = decrypt(amt_rcv, recvd, atm->key, iv, decrypted_text);
		decrypted_text[decrypted_len] = '\0';

		unsigned int net_balance,host_balance;
		memcpy(&net_balance, &decrypted_text[0], decrypted_len);
		
		host_balance = be32toh(net_balance);
		printf("$%d\n", host_balance);
	}
	return 0;
}

int end_session(ATM *atm) 
{
	if(atm->logged_in == NULL)
	{
		printf("No user is logged in\n");
		return -1;
	}
	else{
		atm->attempts = 0;
		atm->logged_in = NULL;

		printf("User logged out\n");
		return 0;
	}

}

void atm_process_command(ATM *atm, char *command)
{
	char *input  = (char*)malloc(sizeof(char) * MAX_NAME_LEN + 1 );
	bzero(input, MAX_NAME_LEN + 1);

	int cmd = 0, amt = -1;
	cmd = check_command(atm, command, input);
	switch(cmd)
	{
		case 1:
			if( check_user_name(atm,input)  != 0 )
				return;

			if( begin_session(atm, input) != 0 ){
				return;
			}
			break;

		case 2:

			if( (amt = check_amt(atm, input)) < 0){
				return;
			}

			if( withdraw(atm, amt) != 0){
				return;
			}
			break;
		
		case 3:
			if( balance(atm) != 0){
				return;
			}
			break;
		
		case 4:
			if( end_session(atm) != 0){
				return;
			}
			break;

		default:
			break;
	}
}
