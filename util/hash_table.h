/*
 * This is a simple hash table that maps a char* key to a void* data.
 * It does not permit multiple entires with the same key.
 * See hash_table_example.c for an example of how to use it.
 * Feel free to change this as you desire.
 */

#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

#include "list.h"
#include <stdint.h>

typedef struct _HashTable
{
    uint32_t num_bins;
    List **bins;
    uint32_t size;
} HashTable;

HashTable* hash_table_create(uint32_t num_bins);
void hash_table_free(HashTable *ht);
uint32_t hash(const char * data, int len);
void hash_table_add(HashTable *ht, char *key, void *val);
void* hash_table_find(HashTable *ht, const char *key);
void hash_table_del(HashTable *ht, const char *key);
uint32_t hash_table_size(const HashTable *ht);

#endif
