#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"

List* list_create()
{
    List *list = (List*) malloc(sizeof(List));
    list->head = list->tail = NULL;
    list->size = 0;
    return list;
}

void list_free(List *list)
{
    if(list != NULL)
    {
        ListElem *curr = list->head;
        ListElem *next;
        while(curr != NULL)
        {
            next = curr->next;
            free(curr->pin);
            free(curr->key);
            free(curr);
            curr = next;
        }
        free(list);
    }
}

ListElem* list_find(List *list, const char *key)
{
    if(list == NULL)
        return NULL;

    ListElem *curr = list->head;
    while(curr != NULL)
    {
        if(strcmp(curr->key, key) == 0)
            return curr;
        curr = curr->next;
    }

    return NULL;
}

void list_add(List *list, char *key, int *bal, char *pin, char *card_content)
{
    ListElem *elem = (ListElem*) malloc(sizeof(ListElem));
    elem->key = malloc(sizeof(char) * 251);
    strcpy(elem->key, key);

    elem->balance = *bal;
    
    elem->pin = malloc(sizeof(char) * 251);
    strcpy(elem->pin, pin);
    
    elem->card_content = malloc(sizeof(char) * 65);
    strncpy(elem->card_content,card_content,strlen(card_content)+1);
    
    elem->next = NULL;

    if(list->tail == NULL)
        list->head = list->tail = elem;
    else{
        list->tail->next = elem;
        list->tail = elem;
    }

    list->size++;
}

void list_del(List *list, const char *key)
{
    // Remove the element with key 'key'
    ListElem *curr, *prev;

    curr = list->head;
    prev = NULL;
    while(curr != NULL)
    {
        if(strcmp(curr->key, key) == 0)
        {
            // Found it: now delete it

            if(curr == list->tail)
                list->tail = prev;

            if(prev == NULL)
                list->head = list->head->next;
            else
                prev->next = curr->next;

            list->size--;
            free(curr->key);
            free(curr->pin);
            free(curr->card_content);
            free(curr);
            return;
        }

        prev = curr;
        curr = curr->next;
    }
}

uint32_t list_size(const List *list)
{
    return list->size;
}
