#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hash_table.h"

HashTable* hash_table_create(uint32_t num_bins)
{
    HashTable *ht;
    uint32_t i;
   
    ht = (HashTable*) malloc(sizeof(HashTable));
    ht->num_bins = num_bins;
    ht->bins = (List**) malloc(sizeof(List*) * num_bins);

    for(i=0; i < num_bins; i++)
        ht->bins[i] = list_create();

    ht->size = 0;

    return ht;
}

void hash_table_free(HashTable *ht)
{
    uint32_t i;

    if(ht != NULL)
    {
        for(i=0; i < ht->num_bins; i++)
            list_free(ht->bins[i]);

        free(ht->bins);
        free(ht);
    }
}

// From http://www.azillionmonkeys.com/qed/hash.html
uint32_t hash(const char * data, int len)
{
#define get16bits(d) (*((const uint16_t *) (d)))

    uint32_t hash = len, tmp;
    int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= ((signed char)data[sizeof (uint16_t)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

void hash_table_add(HashTable *ht, char *key, void *val)
{
    uint32_t idx = hash(key, strlen(key)) % ht->num_bins;

    // Do not permit duplicates
    if(list_find(ht->bins[idx], key) == NULL)
    {
        ht->size -= list_size(ht->bins[idx]);
        list_add(ht->bins[idx], key, val);
        ht->size += list_size(ht->bins[idx]);
    }
}

void* hash_table_find(HashTable *ht, const char *key)
{
    uint32_t idx = hash(key, strlen(key)) % ht->num_bins;
    return list_find(ht->bins[idx], key);
}

void hash_table_del(HashTable *ht, const char *key)
{
    uint32_t idx = hash(key, strlen(key)) % ht->num_bins;

    ht->size -= list_size(ht->bins[idx]);
    list_del(ht->bins[idx], key);
    ht->size += list_size(ht->bins[idx]);
}

uint32_t hash_table_size(const HashTable *ht)
{
    return ht->size;
}
