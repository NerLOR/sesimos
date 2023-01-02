
#include <criterion/criterion.h>
#include <criterion/parameterized.h>

#include "../src/lib/list.h"

Test(list, simple) {
    int v;
    int *list = list_create(sizeof(int), 16);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 0);

    v = 1;
    list = list_append(list, &v);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 1);
    cr_assert_eq(list[0], 1);

    v = 3;
    list = list_append(list, &v);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 2);
    cr_assert_eq(list[0], 1);
    cr_assert_eq(list[1], 3);

    v = 2;
    list = list_insert(list, &v, 1);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 3);
    cr_assert_eq(list[0], 1);
    cr_assert_eq(list[1], 2);
    cr_assert_eq(list[2], 3);

    list = list_remove(list, 0);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 2);
    cr_assert_eq(list[0], 2);
    cr_assert_eq(list[1], 3);

    list = list_remove(list, 1);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 1);
    cr_assert_eq(list[0], 2);

    list = list_remove(list, 0);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 0);

    list_free(list);
}

Test(list, resize) {
    int v;
    int *list = list_create(sizeof(int), 4);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 0);

    for (int i = 0; i < 4096; i++) {
        v = 9182 - i;
        list = list_append(list, &v);
        cr_assert_not_null(list);
        cr_assert_eq(list_size(list), i + 1);
    }

    for (int i = 0; i < 4096; i++) {
        list = list_remove(list, -1);
        cr_assert_not_null(list);
        cr_assert_eq(list_size(list), 4096 - i - 1);
    }

    for (int i = 0; i < 4096; i++) {
        v = 9182 - i;
        list = list_append(list, &v);
        cr_assert_not_null(list);
        cr_assert_eq(list_size(list), i + 1);
    }

    list = list_clear(list);
    cr_assert_not_null(list);
    cr_assert_eq(list_size(list), 0);

    list_free(list);
}
