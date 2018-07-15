/* SPDX-License-Identifier: GPL-2.0 */
/* linux/net/inet/arp.h */
#ifndef _ARP_H
#define _ARP_H

#include <linux/if_arp.h>
#include <linux/hash.h>
#include <net/neighbour.h>

static inline struct neigh_table *ipv4_neigh_table(struct net *net)
{
	return net->ipv4.arp_tbl;
}

static inline struct neighbour *ipv4_neigh_create(struct net_device *dev,
						  const void *pkey)
{
	return neigh_create(ipv4_neigh_table(dev_net(dev)), pkey, dev);
}

static inline struct neighbour *ipv4_neigh_create_noref(struct net_device *dev,
							const void *pkey)
{
	return __neigh_create(ipv4_neigh_table(dev_net(dev)), pkey, dev, false);
}

static inline struct neighbour *ipv4_neigh_lookup(struct net_device *dev,
						  void *key)
{
	return neigh_lookup(ipv4_neigh_table(dev_net(dev)), key, dev);
}

static inline u32 arp_hashfn(const void *pkey, const struct net_device *dev, u32 *hash_rnd)
{
	u32 key = *(const u32 *)pkey;
	u32 val = key ^ hash32_ptr(dev);

	return val * hash_rnd[0];
}

static inline struct neighbour *__ipv4_neigh_lookup_noref(struct net_device *dev, u32 key)
{
	if (dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
		key = INADDR_ANY;

	return ___neigh_lookup_noref(ipv4_neigh_table(dev_net(dev)),
				     neigh_key_eq32, arp_hashfn, &key, dev);
}

static inline struct neighbour *__ipv4_neigh_lookup(struct net_device *dev, u32 key)
{
	struct neighbour *n;

	rcu_read_lock_bh();
	n = __ipv4_neigh_lookup_noref(dev, key);
	if (n && !refcount_inc_not_zero(&n->refcnt))
		n = NULL;
	rcu_read_unlock_bh();

	return n;
}

static inline void __ipv4_confirm_neigh(struct net_device *dev, u32 key)
{
	struct neighbour *n;

	rcu_read_lock_bh();
	n = __ipv4_neigh_lookup_noref(dev, key);
	if (n) {
		unsigned long now = jiffies;

		/* avoid dirtying neighbour */
		if (n->confirmed != now)
			n->confirmed = now;
	}
	rcu_read_unlock_bh();
}

void arp_init(void);
int arp_ioctl(struct net *net, unsigned int cmd, void __user *arg);
void arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw,
	      const unsigned char *src_hw, const unsigned char *th);
int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir);
void arp_ifdown(struct net_device *dev);

struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw);
void arp_xmit(struct sk_buff *skb);

#endif	/* _ARP_H */
