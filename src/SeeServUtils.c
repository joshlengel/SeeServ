#include"SeeServUtils.h"

#include<stdint.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>

void vector_create(Vector *vector, size_t element_size)
{
    assert(vector != NULL);

    vector->capacity = 10;
    vector->size = 0;
    vector->element_size = element_size;

    vector->data = malloc(vector->capacity * element_size);
}

void vector_push_back(Vector *vector, const void *elem)
{
    assert(vector != NULL);

    if (vector->capacity <= vector->size)
    {
        size_t new_capacity = vector->capacity * 2;
        vector->data = realloc(vector->data, new_capacity * vector->element_size);
        assert(vector->data != NULL);
        vector->capacity = new_capacity;
    }

    memcpy((int8_t*)vector->data + vector->size * vector->element_size, elem, vector->element_size);
    ++vector->size;
}

void vector_pop_front(Vector *vector, void *dst)
{
    assert(vector != NULL);
    assert(vector->size > 0);
    assert(dst != NULL);

    memcpy(dst, vector->data, vector->element_size);
    memmove(vector->data, (int8_t*)vector->data + vector->element_size, (vector->size - 1) * vector->element_size);
    --vector->size;
}

void vector_query(const Vector *vector, size_t i, void *dst)
{
    assert(vector != NULL);
    assert(i < vector->size);
    assert(dst != NULL);

    memcpy(dst, (int8_t*)vector->data + i * vector->element_size, vector->element_size);
}

void *vector_get(Vector *vector, size_t i)
{
    assert(vector != NULL);
    assert(i < vector->size);

    return (int8_t*)vector->data + i * vector->element_size;
}

void vector_remove(Vector *vector, size_t i)
{
    assert(vector != NULL);
    assert(i < vector->size);

    int8_t *location = (int8_t*)vector->data + i * vector->element_size;
    memmove(location, location + vector->element_size, (vector->size - i - 1) * vector->element_size);
    --vector->size;
}

void vector_shrink(Vector *vector)
{
    assert(vector != NULL);

    vector->data = realloc(vector->data, vector->size * vector->element_size);
    vector->capacity = vector->size;
}

void vector_destroy(Vector *vector)
{
    assert(vector != NULL);
    
    free(vector->data);
}