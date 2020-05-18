/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 10000
static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    char user_input[BUFSIZE];
	
    ATM *atm = atm_create();
	
	char *atm_filename = argv[1];
	if( check_file(atm, atm_filename) != 0)
		return 64;

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, BUFSIZE, stdin) != NULL)
    {
		user_input[strlen(user_input) - 1] = '\0';
        atm_process_command(atm, user_input);
		if(atm->logged_in == NULL){
        	printf("%s", prompt);
		}
		else
		{
			printf("ATM (%s): ",atm->logged_in);
		}
		fflush(stdout);
    }
	return EXIT_SUCCESS;
}
