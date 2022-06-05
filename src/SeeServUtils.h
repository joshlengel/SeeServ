#pragma once

#include<stddef.h>

struct _Vector
{
    size_t capacity, size;
    size_t element_size;
    void *data;
};
typedef struct _Vector Vector;

void vector_create(Vector *vector, size_t element_size);
void vector_push_back(Vector *vector, const void *elem);
void vector_pop_front(Vector *vector, void *dst);
void vector_query(const Vector *vector, size_t i, void *dst);
void *vector_get(Vector *vector, size_t i);
void vector_remove(Vector *vector, size_t i);
void vector_shrink(Vector *vector);
void vector_destroy(Vector *vector);