#include "../include/glist.h"

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

static status_val shrink_glist(struct glist *lst)
{
	if (lst->cap > 1) {
		void **new_array = calloc(lst->cap / 2, sizeof(void *));
		if (!new_array) {
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		memcpy(new_array, lst->array, sizeof(void *) * lst->cap / 2);
		free(lst->array);
		lst->array = new_array;
		lst->cap /= 2;
		return STATUS_OK;
	}

	return STATUS_ERROR;
}

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

//cap must be power of 2 and highier than 0, if not defaults to 16;
struct glist *glist_new(int cap, float shrink_thr)
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
	lst->min_cap = cap;
	lst->shrink_threshold = shrink_thr;

	void **array = calloc(cap, sizeof(void *));
	if (!array) {
		free(lst);
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	lst->array = array;
	return lst;
}

struct glist *glist_clone(struct glist *lst)
{
	struct glist *clone = calloc(1, sizeof(struct glist));
	if (!lst) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	memcpy(clone, lst, sizeof(struct glist));
	clone->array = calloc(lst->cap, sizeof(void *));
	if (!clone->array) {
		free(clone);
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	memcpy(clone->array, lst->array, sizeof(void *) * lst->cap);
	if (clone->clone_cb) {
		for (size_t i = 0; i < lst->count; i++) {
			clone->clone_cb(&(clone->array[i]), lst->array[i]);
		}
	}

	return clone;
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

status_val glist_push2(struct glist *lst, void *value, size_t len)
{
	status_val status;

	void *data = calloc(1, len);
	if (!data) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	if (!memcpy(data, value, len)) {
		LOG(L_CRIT, STATUS_ERROR);
		return STATUS_OMEM;
	}

	if (lst->count == lst->cap && (status = extend_glist(lst))) {
		LOG(L_ERR, status);
		return status;
	}

	lst->array[lst->count++] = data;
	return STATUS_OK;
}

status_val glist_insert(struct glist *lst, void *value, int index)
{
	status_val status;
	int idx = index;

	if (lst->count == lst->cap && (status = extend_glist(lst))) {
		LOG(L_ERR, status);
		return status;
	}

	if (convert_index_glist(lst, &idx) || (size_t)idx > lst->count) {
		LOG(L_ERR, STATUS_BAD_INPUT);
		return STATUS_BAD_INPUT;
	}

	for (size_t i = lst->count; i > (size_t)idx; i--) {
		lst->array[i] = lst->array[i - 1];
	}

	lst->array[idx] = value;
	lst->count++;

	return STATUS_OK;
}

status_val glist_insert2(struct glist *lst, void *value, size_t len, int index)
{
	status_val status;
	int idx = index;

	if (lst->count == lst->cap && (status = extend_glist(lst))) {
		LOG(L_ERR, status);
		return status;
	}

	if (convert_index_glist(lst, &idx) || (size_t)idx > lst->count) {
		LOG(L_ERR, STATUS_BAD_INPUT);
		return STATUS_BAD_INPUT;
	}

	void *data = calloc(1, len);
	if (!data) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	if (!memcpy(data, value, len)) {
		LOG(L_CRIT, STATUS_ERROR);
		return STATUS_OMEM;
	}

	for (size_t i = lst->count; i > (size_t)idx; i--) {
		lst->array[i] = lst->array[i - 1];
	}

	lst->array[idx] = data;
	lst->count++;

	return STATUS_OK;
}

status_val glist_pop(struct glist *lst, void **value_ptr)
{
	if (lst->count <= (float)lst->cap * lst->shrink_threshold &&
		lst->count > lst->min_cap && shrink_glist(lst)) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return STATUS_NOT_FOUND;
	}

	*value_ptr = lst->array[--lst->count];

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

status_val glist_get_idx(struct glist *lst, void *value, int *index)
{
	for (size_t i = 0; i < lst->count; i++) {
		if (lst->array[i] == value) {
			*index = (int)i;
			return STATUS_OK;
		}
	}

	return STATUS_NOT_FOUND;
}

void *glist_remove(struct glist *lst, int index)
{
	int idx = index;

	if (convert_index_glist(lst, &idx) || (size_t)idx > lst->count) {
		LOG(L_NOTICE, STATUS_NOT_FOUND);
		return NULL;
	}

	void *value = lst->array[idx];
	for (size_t i = idx; i < lst->count - 1; i++) {
		*(lst->array + i) = *(lst->array + i + 1);
	}

	lst->count--;
	if (lst->count <= (float)lst->cap * lst->shrink_threshold &&
		lst->count > lst->min_cap && shrink_glist(lst)) {
		LOG(L_CRIT, STATUS_ERROR);
		return NULL;
	}

	return value;
}

status_val glist_delete(struct glist *lst, int index)
{
	int idx = index;

	if (convert_index_glist(lst, &idx) || (size_t)idx > lst->count) {
		return STATUS_BAD_INPUT;
	}

	if (lst->free_cb != NULL) {
		lst->free_cb(lst->array[idx]);
	} else {
		free(lst->array[idx]);
	}

	for (size_t i = idx; i < lst->count - 1; i++) {
		*(lst->array + i) = *(lst->array + i + 1);
	}

	lst->count--;
	if (lst->count <= (float)lst->cap * lst->shrink_threshold &&
		lst->count > lst->min_cap && shrink_glist(lst) != 0) {
		LOG(L_CRIT, STATUS_ERROR);
		return STATUS_ERROR;
	}

	return 0;
}

status_val glist_forget(struct glist *lst, int index)
{
	int idx = index;

	if (convert_index_glist(lst, &idx) || (size_t)idx > lst->count) {
		LOG(L_NOTICE, STATUS_BAD_INPUT);
		return STATUS_BAD_INPUT;
	}

	for (size_t i = idx; i < lst->count - 1; i++) {
		*(lst->array + i) = *(lst->array + i + 1);
	}

	lst->count--;

	if (lst->count <= (float)lst->cap * lst->shrink_threshold &&
		lst->count > lst->min_cap && shrink_glist(lst) != 0) {
		LOG(L_CRIT, STATUS_ERROR);
		return STATUS_ERROR;
	}

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

	//could use memncpy for all elements, but this is good enough
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

void **glist_get_array(struct glist *lst)
{
	if (lst)
		return lst->array;
	return NULL;
}

void glist_set_free_cb(struct glist *lst, void (*cb)(void *))
{
	if (lst)
		lst->free_cb = cb;
}

void glist_set_clone_cb(struct glist *lst, void (*cb)(void **, void *))
{
	if (lst)
		lst->clone_cb = cb;
}
