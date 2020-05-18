#include "hash_table.h"
#include <stdio.h>
#include <stdlib.h>

int main()
{
    HashTable *ht = hash_table_create(10);
    printf("Size: %d\n", hash_table_size(ht));

    hash_table_add(ht, "Alice", "123");
    hash_table_add(ht, "Bob", "345");

    printf("Alice -> %s\n", hash_table_find(ht, "Alice"));
    hash_table_del(ht, "Alice");
    hash_table_add(ht, "Alice", "234");
    printf("Alice -> %s\n", hash_table_find(ht, "Alice"));
    printf("Bob -> %s\n", hash_table_find(ht, "Bob"));
    printf("Charlie -> %s\n", (hash_table_find(ht, "charlie") == NULL ? "Not Found" : "FAIL"));

    printf("Size: %d\n", hash_table_size(ht));

    return EXIT_SUCCESS;
}
