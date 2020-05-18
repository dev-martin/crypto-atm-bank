/*
 * The Router forwards packets between the ATM and the Bank.  It
 * takes no commands from stdin.
 *
 * For the first part of the project, you may not modify the router.
 *
 * For the second part of the project, you may modify the router to
 * try to violate the security of other team's protocols.
 */

#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

typedef struct _Router
{
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;
    struct sockaddr_in bank_addr;
} Router;

Router* router_create();
void router_free(Router *rtr);
ssize_t router_recv(Router *rtr,   char *data, size_t max_len, struct sockaddr_in *sender);
ssize_t router_sendto_atm(Router *rtr,   char *data, size_t len);
ssize_t router_sendto_bank(Router *rtr,   char *data, size_t len);


#endif
