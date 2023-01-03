
#include "list.h"

#include <malloc.h>
#include <memory.h>
#include <errno.h>

#define FACTOR 4

typedef struct {
    int init_size, elem_size, max_size, size;
} list_meta_t;

static void *list_resize(list_meta_t *list, int new_size) {
    if (new_size <= 0)
        return NULL;

    list_meta_t *new_ptr = realloc(list, sizeof(list_meta_t) + list->elem_size * new_size);
    if (new_ptr == NULL)
        return NULL;

    new_ptr->max_size = new_size;
    return new_ptr;
}

void *list_create(int elem_size, int init_elem_n) {
    if (elem_size <= 0 || init_elem_n <= 0) {
        errno = EINVAL;
        return NULL;
    }

    void *list_ptr = malloc(sizeof(list_meta_t) + elem_size * init_elem_n);
    list_meta_t *list = list_ptr;
    list->init_size = init_elem_n;
    list->elem_size = elem_size;
    list->max_size = init_elem_n;
    list->size = 0;
    return (unsigned char *) list_ptr + sizeof(list_meta_t);
}

int list_size(const void *list_ptr) {
    list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
    return list->size;
}

void *list_insert(void *list_ptr, void *elem, int n) {
    void *ptr = NULL;
    list_ptr = list_insert_ptr(list_ptr, &ptr, n);
    if (list_ptr != NULL && ptr != NULL) {
        list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
        memcpy(ptr, elem, list->elem_size);
    }

    return list_ptr;
}

void *list_insert_ptr(void *list_ptr, void **elem, int n) {
    list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
    if (n < 0)
        n = list->size + n + 1;

    if (list->size >= list->max_size) {
        if ((list = list_resize(list, list->max_size * FACTOR)) == NULL) {
            return NULL;
        }
    }

    unsigned char *array = (unsigned char *) list + sizeof(list_meta_t);

    if (n < list->size)
        memmove(array + (n + 1) * list->elem_size, array + n * list->elem_size, (list->size - n) * list->elem_size);
    *elem = array + n * list->elem_size;

    list->size++;
    return (unsigned char *) list + sizeof(list_meta_t);
}

void *list_append(void *list_ptr, void *elem) {
    return list_insert(list_ptr, elem, -1);
}

void *list_append_ptr(void *list_ptr, void **elem) {
    return list_insert_ptr(list_ptr, elem, -1);
}

void *list_remove(void *list_ptr, int n) {
    list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
    if (n < 0)
        n = list->size + n;

    unsigned char *array = list_ptr;

    if (list->size > 1 && n < list->size)
        memmove(array + n * list->elem_size, array + (n + 1) * list->elem_size, (list->size - n - 1) * list->elem_size);

    list->size--;
    if (list->size < list->max_size / FACTOR && list->max_size / FACTOR >= list->init_size) {
        if ((list = list_resize(list, list->max_size / FACTOR)) == NULL) {
            return NULL;
        }
    }

    return (unsigned char *) list + sizeof(list_meta_t);
}

void *list_clear(void *list_ptr) {
    list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
    list->size = 0;
    memset(list_ptr, 0, list->max_size * list->elem_size);
    list->max_size = list->init_size;
    return (unsigned char *) list_resize(list, list->max_size * list->elem_size) + sizeof(list_meta_t);
}

void list_free(void *list_ptr) {
    list_meta_t *list = (void *) ((unsigned char *) list_ptr - sizeof(list_meta_t));
    free(list);
}
