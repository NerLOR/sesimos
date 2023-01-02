
#ifndef SESIMOS_LIST_H
#define SESIMOS_LIST_H

void *list_create(int elem_size, int init_elem_n);

unsigned int list_size(void *list_ptr);

void *list_insert(void *list_ptr, void *elem, int n);

void *list_append(void *list_ptr, void *elem);

void *list_remove(void *list_ptr, int n);

void *list_clear(void *list_ptr);

void list_free(void *list_ptr);

#endif //SESIMOS_LIST_H
