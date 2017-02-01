/*
 */

#ifndef _FIB_TRIE_H
#define _FIB_TRIE_H

extern struct fib_ops fib_trie_ops;

struct fib_table *fib_trie_new_table(struct net *net, u32 id);
struct fib_table *fib_trie_get_table(struct net *net, u32 id);

#endif  /* _NET_FIB_H */
