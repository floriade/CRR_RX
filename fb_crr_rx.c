/*
 * Lightweight Autonomic Network Architecture
 *
 * crr_rx test module.
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/if_ether.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#define ETH_HDR_LEN	14
#define WIN_SZ		2

struct fb_crr_rx_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t rx_lock;
	unsigned char rx_seq_nr;
	struct sk_buff_head *list;
};

/*static struct sk_buff *skb_get_pos(unsigned char seq, 
					 struct sk_buff_head *list);*/

/* returns a pointer to the skb_buff with the following seq number */
static struct sk_buff *skb_get_pos(unsigned char seq, struct sk_buff_head *list)
{
	struct sk_buff *curr = list->next;

	/* list is empty */
	if (list->next == list->prev)
		return list->next;
	/* Second element */
	else if (seq == 2)
		return list->next;
	/* others */
	while(1) {
	if (curr->cb[47] > seq)
		break;
	
		if (curr->next == list->next)
			break;
		curr = curr->next;
	}
	return curr;
}

static int fb_crr_rx_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int i;
	unsigned char mac_src[14];
	unsigned char mac_dst[14];
	unsigned char custom, seq, ack;
	struct sk_buff *skb_last, *cloned_skb;
	struct fb_crr_rx_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->lock, seq));
	/* Send */
	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {

	}
	/* Receive */
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {
		cloned_skb = NULL;
		custom = *(skb->data + ETH_HDR_LEN);
		seq = custom >> 4;
		ack = custom & 0xF;
		/* Correct sequence number: */		
		/* Pass current and in line packets */
		write_lock(&fb_priv_cpu->rx_lock);		
		if (seq == fb_priv_cpu->rx_seq_nr) { /* R */
			/* First element */
			skb_last = fb_priv_cpu->list->next; /* R */
			/* iterate over nr elements in queue */
			for (i = 1; i <= fb_priv_cpu->list->qlen; i++) { /* R */
				if (skb_last->cb[47] == seq + i) {
					/* if next seq nr in buffer -> schedule */
					/* remove from list */
					skb_unlink(skb_last, fb_priv_cpu->list); /* W */
					engine_backlog_tail(skb_last, *dir);
				}
				else
					/* if next missing -> break */
					break;

				skb_last = skb_last->next;	/* R */		
			}

			if (fb_priv_cpu->rx_seq_nr++ == 2*WIN_SZ) /* W */
				fb_priv_cpu->rx_seq_nr = 1;	/* W */
			write_unlock(&fb_priv_cpu->rx_lock);
		}
		/* Wrong sequence number: */
		/* Keep packet in buffer */
		else {
			/* write seq nr in control buffer */
			skb->cb[47] = seq;
			/* find correct position */
			skb_last = skb_get_pos(seq, fb_priv_cpu->list); /* R */
			/* insert to position */
			skb_insert(skb_last, skb, fb_priv_cpu->list); /* W */
			write_unlock(&fb_priv_cpu->rx_lock);
			drop = 2;
		}
		goto ACK;
	}
back:	
	if (drop == 1) {
		kfree_skb(skb);
		return PPE_DROPPED;
	}
	else if (drop == 2)
		return PPE_DROPPED;
	return PPE_SUCCESS;
ACK:
	if ((cloned_skb = skb_copy(skb, GFP_ATOMIC))) {
		/* Swap MAC Addresses */
		memcpy(eth_hdr(cloned_skb)->h_source, mac_src, 14);
		memcpy(eth_hdr(cloned_skb)->h_dest, mac_dst, 14);
		memcpy(mac_dst, eth_hdr(cloned_skb)->h_source, 14);
		memcpy(mac_src, eth_hdr(cloned_skb)->h_dest, 14);
		/* Write ACK Code */
		custom = custom | 0xF;
		*(cloned_skb->data + ETH_HDR_LEN) = custom;
		/* change idp order */
		read_lock(&fb_priv_cpu->rx_lock);		
		write_next_idp_to_skb(cloned_skb, fb_priv_cpu->port[TYPE_EGRESS], fb->idp); /* R on port */
		read_unlock(&fb_priv_cpu->rx_lock);
		/* schedule packet */
		engine_backlog_tail(cloned_skb, TYPE_EGRESS);
	}
	goto back;

}

static int fb_crr_rx_event(struct notifier_block *self, unsigned long cmd,
			  void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_crr_rx_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_crr_rx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

#ifdef __DEBUG
	printk("Got event %lu on %p!\n", cmd, fb);
#endif

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_crr_rx_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (bound)
			printk(KERN_INFO "[%s::%s] port %s bound to IDP%u\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir], msg->idp);
		} break;
	case FBLOCK_UNBIND_IDP: {
		int unbound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_crr_rx_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::%s] port %s unbound\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir]);
		} break;
	case FBLOCK_SET_OPT: {
		struct fblock_opt_msg *msg = args;
		printk("Set option %s to %s!\n", msg->key, msg->val);
		} break;
	default:
		break;
	}

	return ret;
}

static struct fblock *fb_crr_rx_ctor(char *name)
{
	int ret = 0;
	unsigned int cpu;
	struct sk_buff_head *tmp_list;
	struct fblock *fb;
	struct fb_crr_rx_priv __percpu *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_crr_rx_priv);
	if (!fb_priv)
		goto err;

	if (unlikely((tmp_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Decoding failed!\n");
		goto err1;
	}
	skb_queue_head_init(tmp_list);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_crr_rx_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		rwlock_init(&fb_priv_cpu->rx_lock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->rx_seq_nr = 1;
		fb_priv_cpu->list = tmp_list;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_crr_rx_netrx;
	fb->event_rx = fb_crr_rx_event;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	printk(KERN_ERR "Initialization passed!\n");
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	kfree(tmp_list);
err1:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_crr_rx_dtor(struct fblock *fb)
{
	int i;
	struct fb_crr_rx_priv *fb_priv_cpu;
	struct fb_crr_rx_priv __percpu *fb_priv;

	rcu_read_lock();
	fb_priv = (struct fb_crr_rx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	/* CPUs share same priv. d */
	rcu_read_unlock();

	write_lock(&fb_priv_cpu->rx_lock);
	for (i = 0; i < fb_priv_cpu->list->qlen; i++) {
		/* TODO: kfree() und list->next updaten */
		 skb_unlink(fb_priv_cpu->list->next, fb_priv_cpu->list);
	}
	kfree(fb_priv_cpu->list);
	write_unlock(&fb_priv_cpu->rx_lock);

	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
	printk(KERN_ERR "Deinitialization passed!\n");
}

static struct fblock_factory fb_crr_rx_factory = {
	.type = "crr_rx",
	.mode = MODE_DUAL,
	.ctor = fb_crr_rx_ctor,
	.dtor = fb_crr_rx_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_crr_rx_module(void)
{
	return register_fblock_type(&fb_crr_rx_factory);
}

static void __exit cleanup_fb_crr_rx_module(void)
{
	synchronize_rcu();
	unregister_fblock_type(&fb_crr_rx_factory);
}

module_init(init_fb_crr_rx_module);
module_exit(cleanup_fb_crr_rx_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Florian Deragisch <floriade@ee.ethz.ch>");
MODULE_DESCRIPTION("LANA CRR RX module");
