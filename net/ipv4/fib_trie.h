/*
 */

#ifndef _FIB_TRIE_H
#define _FIB_TRIE_H

extern struct fib_ops fib_trie_ops;

struct fib_table *fib_trie_new_table(struct net *net, u32 id);
struct fib_table *fib_trie_get_table(struct net *net, u32 id);
int fib_trie_table_lookup(struct fib_table *tb,
                          const struct flowi4 *flp,
                          struct fib_result *res, int fib_flags);
int __fib_trie_lookup(struct net *net, struct flowi4 *flp,
		      struct fib_result *res, unsigned int flags);
int fib_trie_unmerge(struct net *net);

int __net_init fib4_rules_init(struct net *net);
void __net_exit fib4_rules_exit(struct net *net);

#endif  /* _NET_FIB_H */
