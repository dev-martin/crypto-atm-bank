#include "router.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

Router* router_create()
{
    Router *router = (Router*) malloc(sizeof(Router));
    if(router == NULL)
    {
        perror("Could not malloc Router");
        exit(1);
    }

    router->sockfd = socket(AF_INET,SOCK_DGRAM,0);

    // Initialize router's address
    bzero(&router->rtr_addr,sizeof(router->rtr_addr));
    router->rtr_addr.sin_family = AF_INET;
    router->rtr_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    router->rtr_addr.sin_port=htons(ROUTER_PORT);
    bind(router->sockfd,(struct sockaddr *)&router->rtr_addr,sizeof(router->rtr_addr));

    // Initialize Bank's address
    bzero(&router->bank_addr,sizeof(router->bank_addr));
    router->bank_addr.sin_family = AF_INET;
    router->bank_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    router->bank_addr.sin_port=htons(BANK_PORT);

    // Initialize ATM's address
    bzero(&router->atm_addr,sizeof(router->atm_addr));
    router->atm_addr.sin_family = AF_INET;
    router->atm_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    router->atm_addr.sin_port=htons(ATM_PORT);

    return router;
}

void router_free(Router *router)
{
    if(router != NULL)
    {
        close(router->sockfd);
        free(router);
    }
}

ssize_t router_recv(Router *router, char *data, size_t max_len, struct sockaddr_in *sender)
{
    socklen_t len = 0;
    if(sender != NULL)
        len = sizeof(*sender);
    return recvfrom(router->sockfd, data, max_len, 0, (struct sockaddr*) sender, &len);
}

ssize_t router_sendto_atm(Router *router, char *data, size_t len)
{
    return sendto(router->sockfd, data, len, 0,
           (struct sockaddr *)&router->atm_addr, sizeof(router->atm_addr));
}

ssize_t router_sendto_bank(Router *router, char *data, size_t len)
{
    return sendto(router->sockfd, data, len, 0,
           (struct sockaddr *)&router->bank_addr, sizeof(router->bank_addr));
}
