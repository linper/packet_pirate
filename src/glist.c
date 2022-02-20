/**
 * @file glist.c
 * @brief Implementation of generic list data structure interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include "../include/glist.h"

/**
 * @brief Doubles capacity of list and copies entries to new array
 * @param[in, out] *lst	Pointer to list to extend
 * @return STATUS_OK if successful
 */
static status_val extend_glist(struct glist *lst)
{
	void **new_array = calloc(lst->cap * 2, sizeof(void *));

	if (!new_array) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	memcpy(new_array, lst->array, sizeof(void *) * lst->cap);
	free(lst->array);
	lst->array = new_array;
	lst->cap *= 2;

	return STATUS_OK;
}

/**
 * @brief Enables indexing by negative indices
 * @param[in] *lst			Pointer to to retrieve modefied index from
 * @param[in, out] *index 	Index to be conferted to non negative
 * @return STATUS_OK if successful
 */
static status_val convert_index_glist(struct glist *lst, int *index)
{
	int count = (int)lst->count;
	int index_val = *index;

	if ((count + index_val) < 0) {
		return STATUS_BAD_INPUT;
	}

	if (index_val >= 0) {
		return STATUS_OK;
	}

	*index = count + index_val;
	return STATUS_OK;
}

struct glist *glist_new(int cap)
{
	if (cap < 1 || cap % 2 == 1) {
		cap = 16;
	}

	struct glist *lst = calloc(1, sizeof(struct glist));
	if (!lst) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	lst->cap = cap;

	void **array = calloc(cap, sizeof(void *));
	if (!array) {
		free(lst);
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	lst->array = array;
	return lst;
}

void glist_clear(struct glist *lst)
{
	for (size_t i = 0; i < lst->count; i++) {
		if (lst->free_cb != NULL) {
			lst->free_cb(lst->array[i]);
		} else {
			free(lst->array[i]);
		}
	}
	lst->count = 0;
}

void glist_clear_shallow(struct glist *lst)
{
	if (lst) {
		lst->count = 0;
	}
}

void glist_free(struct glist *lst)
{
	if (lst != NULL) {
		glist_clear(lst);
		free(lst->array);
		free(lst);
	}
}

void glist_free_shallow(struct glist *lst)
{
	if (lst != NULL) {
		free(lst->array);
		free(lst);
	}
}

status_val glist_push(struct glist *lst, void *value)
{
	status_val status;

	if (lst->count == lst->cap && (status = extend_glist(lst))) {
		LOG(L_ERR, status);
		return status;
	}

	lst->array[lst->count++] = value;
	return STATUS_OK;
}

status_val glist_get(struct glist *lst, int index, void **value)
{
	int idx = index;
	if (convert_index_glist(lst, &idx) || (size_t)idx >= lst->count) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return STATUS_NOT_FOUND;
	}

	*value = lst->array[idx];
	return STATUS_OK;
}

status_val glist_copy_to(struct glist *src, struct glist *dst)
{
	status_val status;

	while (src->count + dst->count >= dst->cap) {
		if ((status = extend_glist(dst))) {
			LOG(L_ERR, status);
			return status;
		}
	}

	for (size_t i = 0; i < src->count; i++) {
		dst->array[dst->count++] = src->array[i];
	}

	return STATUS_OK;
}

size_t glist_count(struct glist *lst)
{
	if (lst)
		return lst->count;
	return 0;
}

void glist_set_free_cb(struct glist *lst, void (*cb)(void *))
{
	if (lst)
		lst->free_cb = cb;
}

