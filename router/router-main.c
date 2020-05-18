/* 
 * The main program for the Router.
 *
 * For the first part of the project, you may not change this.
 *
 * For the second part of the project, feel free to change as necessary.
 */


#include <stdio.h>
#include <stdlib.h>
#include "router.h"
#include "ports.h"

int main(int argc, char**argv)
{
   int n;
   char mesg[1000];
   struct sockaddr_in incoming_addr;

   Router *router = router_create();

   while(1)
   {
       n = router_recv(router, mesg, 1000, &incoming_addr);

       unsigned short incoming_port = ntohs(incoming_addr.sin_port);

       // Packet from the ATM: forward it to the bank
       if(incoming_port == ATM_PORT)
       {
           router_sendto_bank(router, mesg, n);
       }

       // Packet from the bank: forward it to the ATM
       else if(incoming_port == BANK_PORT)
       {
           router_sendto_atm(router, mesg, n);
       }

       else
       {
           fprintf(stderr, "> I don't know who this came from: dropping it\n");
       }
   }

   return EXIT_SUCCESS;
}
