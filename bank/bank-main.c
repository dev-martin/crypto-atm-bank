/*
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

#define BUFSIZE 10000
static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
   int n, decrypt_len;
   char sendline[BUFSIZE];
   unsigned char recvline[BUFSIZE], decrypted_text[BUFSIZE];
   bzero(recvline, BUFSIZE);

   unsigned char *iv = (unsigned char *) "alexhaimartindav";

   Bank *bank = bank_create();

   char *bank_filename = argv[1];
   if( check_file(bank, bank_filename) != 0)
		return 64;

   List *clients = list_create();

   printf("%s", prompt);
   fflush(stdout);

   while(1)
   {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, BUFSIZE, stdin);
           sendline[strlen(sendline)-1] = '\0'; 
           bank_process_local_command(bank, clients, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
            n = bank_recv(bank, recvline, BUFSIZE);

            decrypt_len = decrypt(recvline, n, bank->key, iv, decrypted_text);
            decrypted_text[decrypt_len] = '\0';

            bank_process_remote_command(bank, clients, decrypted_text, decrypt_len);
       }
   }

   list_free(clients);

   return EXIT_SUCCESS;
}
