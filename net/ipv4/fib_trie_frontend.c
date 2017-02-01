/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: FIB frontend.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ip_fib.h>
#include <net/rtnetlink.h>
#include <net/xfrm.h>
#include <net/l3mdev.h>
#include <net/lwtunnel.h>
#include <trace/events/fib.h>
#include "fib_trie.h"

#ifndef CONFIG_IP_MULTIPLE_TABLES

static int __net_init fib4_rules_init(struct net *net)
{
	struct fib_table *local_table, *main_table;

	main_table  = fib_trie_table(RT_TABLE_MAIN, NULL);
	if (!main_table)
		return -ENOMEM;

	local_table = fib_trie_table(RT_TABLE_LOCAL, main_table);
	if (!local_table)
		goto fail;

	hlist_add_head_rcu(&local_table->tb_hlist,
				&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX]);
	hlist_add_head_rcu(&main_table->tb_hlist,
				&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX]);
	return 0;

fail:
	fib_free_table(main_table);
	return -ENOMEM;
}

struct fib_table *fib_trie_get_table(struct net *net, u32 id)
{
	struct hlist_node *tb_hlist;
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];

	tb_hlist = rcu_dereference_rtnl(hlist_first_rcu(ptr));

	return hlist_entry(tb_hlist, struct fib_table, tb_hlist);
}

struct fib_table *fib_trie_new_table(struct net *net, u32 id)
{
	return fib_trie_get_table(net, id);
}

#else

/* caller must hold either rtnl or rcu read lock */
struct fib_table *fib_trie_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist) {
		if (tb->tb_id == id)
			return tb;
	}
	return NULL;
}

struct fib_table *fib_trie_new_table(struct net *net, u32 id)
{
	struct fib_table *tb, *alias = NULL;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	tb = fib_trie_get_table(net, id);
	if (tb)
		return tb;

	if (id == RT_TABLE_LOCAL && !net->ipv4.fib_has_custom_rules)
		alias = fib_new_table(net, RT_TABLE_MAIN);

	tb = fib_trie_table(id, alias);
	if (!tb)
		return NULL;

	switch (id) {
	case RT_TABLE_MAIN:
		rcu_assign_pointer(net->ipv4.fib_main, tb);
		break;
	case RT_TABLE_DEFAULT:
		rcu_assign_pointer(net->ipv4.fib_default, tb);
		break;
	default:
		break;
	}

	h = id & (FIB_TABLE_HASHSZ - 1);
	hlist_add_head_rcu(&tb->tb_hlist, &net->ipv4.fib_table_hash[h]);
	return tb;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */

static void fib_replace_table(struct net *net, struct fib_table *old,
			      struct fib_table *new)
{
#ifdef CONFIG_IP_MULTIPLE_TABLES
	switch (new->tb_id) {
	case RT_TABLE_MAIN:
		rcu_assign_pointer(net->ipv4.fib_main, new);
		break;
	case RT_TABLE_DEFAULT:
		rcu_assign_pointer(net->ipv4.fib_default, new);
		break;
	default:
		break;
	}

#endif
	/* replace the old table in the hlist */
	hlist_replace_rcu(&old->tb_hlist, &new->tb_hlist);
}

int fib_unmerge(struct net *net)
{
	struct fib_table *old, *new, *main_table;

	/* attempt to fetch local table if it has been allocated */
	old = fib_trie_get_table(net, RT_TABLE_LOCAL);
	if (!old)
		return 0;

	new = fib_trie_unmerge(old);
	if (!new)
		return -ENOMEM;

	/* table is already unmerged */
	if (new == old)
		return 0;

	/* replace merged table with clean table */
	fib_replace_table(net, old, new);
	fib_free_table(old);

	/* attempt to fetch main table if it has been allocated */
	main_table = fib_trie_get_table(net, RT_TABLE_MAIN);
	if (!main_table)
		return 0;

	/* flush local entries from main table */
	fib_table_flush_external(main_table);

	return 0;
}

static int fib_trie_net_init(struct net *net)
{
	int err;
	size_t size = sizeof(struct hlist_head) * FIB_TABLE_HASHSZ;

	net->ipv4.fib_seq = 0;

	/* Avoid false sharing : Use at least a full cache line */
	size = max_t(size_t, size, L1_CACHE_BYTES);

	net->ipv4.fib_table_hash = kzalloc(size, GFP_KERNEL);
	if (!net->ipv4.fib_table_hash)
		return -ENOMEM;

	err = fib4_rules_init(net);
	if (err < 0)
		goto fail;
	return 0;

fail:
	kfree(net->ipv4.fib_table_hash);
	return err;
}

static void fib_trie_net_exit(struct net *net)
{
	unsigned int i;

	rtnl_lock();
#ifdef CONFIG_IP_MULTIPLE_TABLES
	RCU_INIT_POINTER(net->ipv4.fib_main, NULL);
	RCU_INIT_POINTER(net->ipv4.fib_default, NULL);
#endif
	for (i = 0; i < FIB_TABLE_HASHSZ; i++) {
		struct hlist_head *head = &net->ipv4.fib_table_hash[i];
		struct hlist_node *tmp;
		struct fib_table *tb;

		hlist_for_each_entry_safe(tb, tmp, head, tb_hlist) {
			hlist_del(&tb->tb_hlist);
			fib_table_flush(net, tb);
			fib_free_table(tb);
		}
	}

#ifdef CONFIG_IP_MULTIPLE_TABLES
	fib4_rules_exit(net);
#endif
	rtnl_unlock();
	kfree(net->ipv4.fib_table_hash);
}

struct fib_ops fib_trie_ops = {
	.net_init = fib_trie_net_init,
	.net_exit = fib_trie_net_exit,

	.new_table = fib_trie_new_table,
	.get_table = fib_trie_get_table,
};
