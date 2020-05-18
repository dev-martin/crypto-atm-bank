#include "list.h"
#include <stdio.h>
#include <stdlib.h>


List* test(List *ls, char *b){
  int a = 5;
  list_add(ls, b, &a, "hey");
}
int main()
{
    List *ls = list_create();
    int a = 5;
    char *b = "Alice";
    printf("Charlie -> %s\n", (list_find(ls, "Charlie") == NULL ? "Not Found" : "FAIL"));
    //list_add(ls, "Alice", &a, "hey");
    ls = test(ls, b);
    list_add(ls, "Bob", &a, "hey");

    char *temp = (list_find(ls, "Alice"))->pin;
    printf("Alice -> '%s'\n", temp);
    temp = (list_find(ls, "Bob"))->pin;
    printf("Bob -> '%s'\n", temp);

    //temp = (list_find(ls, "Charlie"))->pin;
    //printf("Charlie -> %s\n", (temp == NULL ? "Not Found" : "FAIL"));

    printf("Size = %d\n", ls->size);
    list_add(ls, "Alice", &a, "hey");
    printf("Size = %d\n", ls->size);
    list_free(ls);

	return EXIT_SUCCESS;
}
