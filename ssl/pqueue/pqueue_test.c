/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdio.h>
#include <string.h>

#include <openssl/pqueue.h>
#include <openssl/ssl.h>


static int trivial() {
  pqueue q = pqueue_new();
  if (q == NULL) {
    return 0;
  }
  int32_t data = 0xdeadbeef;
  uint8_t priority[8] = {0};
  pitem *item = pitem_new(priority, &data);
  if (item == NULL ||
      pqueue_insert(q, item) != item ||
      pqueue_size(q) != 1 ||
      pqueue_peek(q) != item ||
      pqueue_pop(q) != item ||
      pqueue_size(q) != 0 ||
      pqueue_pop(q) != NULL) {
    return 0;
  }
  pitem_free(item);
  pqueue_free(q);
  return 1;
}

#define NUM_ITEMS 10

static int fixed_random() {
  /* Random order of 10 elements, chosen by
     random.choice(list(itertools.permutations(range(10)))) */
  int ordering[NUM_ITEMS] = {9, 6, 3, 4, 0, 2, 7, 1, 8, 5};
  int i;
  pqueue q = pqueue_new();
  if (q == NULL) {
    return 0;
  }
  uint8_t priority[8] = {0};
  /* Insert the elements */
  for (i = 0; i < NUM_ITEMS; i++) {
    priority[7] = ordering[i];
    pitem *item = pitem_new(priority, &ordering[i]);
    pqueue_insert(q, item);
  }
  piterator iter = pqueue_iterator(q);
  pitem *curr = pqueue_next(&iter);
  if (curr == NULL) {
    return 0;
  }
  while (1) {
    pitem *next = pqueue_next(&iter);
    if (next == NULL) {
      break;
    }
    int *curr_data = (int*)curr->data;
    int *next_data = (int*)next->data;
    if (*curr_data >= *next_data) {
      return 0;
    }
    curr = next;
  }
  pqueue_free(q);
  return 1;
}

int main(void) {
  SSL_library_init();

  if (!trivial() || !fixed_random()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
