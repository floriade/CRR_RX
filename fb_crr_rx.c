/*
 * Lightweight Autonomic Network Architecture
 *
 * crr_rx test module.
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

/*
 * ETH_TYPE | SEQ_NR | ACK
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

#define ETH_HDR_LEN	0
#define WIN_SZ		16

struct fb_crr_rx_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t *rx_lock;
	unsigned char *rx_seq_nr;
	struct sk_buff_head *list;
};


/* returns a pointer to the skb_buff with the according seq number */
static struct sk_buff *skb_get_pos(unsigned char seq, struct sk_buff_head *list)
{
	struct sk_buff *curr = list->next;

	if (list->next == (struct sk_buff *)list) {				/* list is empty */
		//printk(KERN_ERR "List is empty\n");		
		return list->next;
	}
	
	else if (seq == 2) {							/* Second element */
		//printk(KERN_ERR "Seqnr 2 -> First element\n");
		return list->next;
	}	
		
	while(1) {								/* Others */
		if (*(curr->data + ETH_HDR_LEN) > seq)
			break;
		else if (*(curr->data + ETH_HDR_LEN) == seq) {		/* identical copy */
			printk(KERN_ERR "Identical copy exists\n");
			return 0;
		}
	
		if (curr->next == (struct sk_buff *)list) {
			//printk(KERN_ERR "Reached end of the list\n");
			return (struct sk_buff *)list;
		}
		curr = curr->next;
	}
	return curr;
}

static int fb_crr_rx_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int i, queue_len;
	unsigned char mac_src[6];
	unsigned char mac_dst[6];
	unsigned char seq, ack;
	struct sk_buff *skb_last, *cloned_skb;
	struct fb_crr_rx_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);			// LOCK
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->lock, seq));			// UNLOCK
	/* Send */
	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {

	}
	/* Receive */
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {
		cloned_skb = NULL;
		seq = *(skb->data + ETH_HDR_LEN);
		ack = *(skb->data + ETH_HDR_LEN+1);
		//printk(KERN_ERR "Received packet\n");
		write_lock(fb_priv_cpu->rx_lock);				// LOCK
		//printk(KERN_ERR "Expected: %d\n", *fb_priv_cpu->rx_seq_nr);
		//printk(KERN_ERR "Received: %d\n", seq);		
		if (seq == *fb_priv_cpu->rx_seq_nr) {
			//printk(KERN_ERR "Correct Seqnr: %d\n", seq);		/* R Correct sequence number: */
			queue_len = skb_queue_len(fb_priv_cpu->list);
			//printk(KERN_ERR "Qlen: %d\n", queue_len);		
			for (i = 1; i <= queue_len; i++) { 			/* R iterate over nr elements in queue */
				//printk(KERN_ERR "%d\n", i);
				skb_last = skb_peek(fb_priv_cpu->list);
				//printk(KERN_ERR "First Seqnr in Queue: %d\n", *(skb_last->data + ETH_HDR_LEN));
				if (*(skb_last->data + ETH_HDR_LEN) == seq + i) {
					//printk(KERN_ERR "Send following Seqnr: %d\n", seq + i);
					skb_last = skb_dequeue(fb_priv_cpu->list);/* Remove first element in list */
					engine_backlog_tail(skb_last, *dir);	/* Send towards user space */
					*fb_priv_cpu->rx_seq_nr = (*fb_priv_cpu->rx_seq_nr % (2*WIN_SZ)) + 1;
				}
				else {
					printk(KERN_ERR "Following Seqnr not found: %d\n", seq + i);	/* if next missing -> break */
					break;
				}	
			}

			*fb_priv_cpu->rx_seq_nr = (*fb_priv_cpu->rx_seq_nr % (2*WIN_SZ)) + 1;
			//printk(KERN_ERR "Next Seqnr expected: %d\n", *fb_priv_cpu->rx_seq_nr);
			write_unlock(fb_priv_cpu->rx_lock);			// UNLOCK
		}
		else {
			//printk(KERN_ERR "Wrong Seqnr: %d\n", seq);		/* Wrong Seq number -> keep in buffer */
			if ((skb_last = skb_get_pos(seq, fb_priv_cpu->list))) {	/* R find correct position */
				skb_insert(skb_last, skb, fb_priv_cpu->list); 	/* W insert to position */
				queue_len = skb_queue_len(fb_priv_cpu->list);
				//printk(KERN_ERR "Added New Qlen: %d\n", queue_len);
				write_unlock(fb_priv_cpu->rx_lock);		// UNLOCK
				drop = 2;
			}
			else {
				write_unlock(fb_priv_cpu->rx_lock);		// UNLOCK
				drop = 1;					/* Received packet for second time */
			}
		}
		//printk(KERN_ERR "Send ACK!\n");
		goto ACK;
	}
back:	
	if (drop == 1) {
		kfree_skb(skb);
		//printk(KERN_ERR "Freed and dropped!\n");
		return PPE_DROPPED;
	}
	else if (drop == 2) {
		//printk(KERN_ERR "Dropped!\n");
		return PPE_DROPPED;
	}
	//printk(KERN_ERR "Passed on!\n");
	return PPE_SUCCESS;
ACK:
	if ((cloned_skb = skb_copy(skb, GFP_ATOMIC))) {				// skb_copy_expand(skb, 14, 0, GFP_ATOMIC)

		skb_push(cloned_skb, 14);
		//skb_set_mac_header(cloned_skb, -14);

		/*for (i = 0; i < 20; i++)
			printk(KERN_ERR "%d\t0x%2x\n", i, *(skb->data-14+i));	
		
		for (i = 0; i < 20; i++)
			printk(KERN_ERR "%d\t0x%2x\n", i, *(cloned_skb->data-14+i));*/
							
		memcpy(mac_src, eth_hdr(cloned_skb)->h_source, 6);		/* Swap MAC Addresses */
		memcpy(mac_dst, eth_hdr(cloned_skb)->h_dest, 6);
		memcpy(eth_hdr(cloned_skb)->h_source, mac_dst, 6);
		memcpy(eth_hdr(cloned_skb)->h_dest, mac_src, 6);
										
		*(cloned_skb->data + ETH_HDR_LEN + 14) = seq;
		*(cloned_skb->data + ETH_HDR_LEN + 14+1) = 0xFF;
										/* change idp order */
		read_lock(fb_priv_cpu->rx_lock);				// LOCK		
		write_next_idp_to_skb(cloned_skb, fb_priv_cpu->port[TYPE_EGRESS], fb->idp); /* R on port */
		read_unlock(fb_priv_cpu->rx_lock);				// UNLOCK
		engine_backlog_tail(cloned_skb, TYPE_EGRESS);			/* schedule packet */
		//printk(KERN_ERR "Send ACK done!\n");	
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
	unsigned char *expected_seq_nr;
	struct sk_buff_head *tmp_list;
	struct fblock *fb;
	struct fb_crr_rx_priv __percpu *fb_priv;
	rwlock_t *tmp_rx_lock;

	

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_crr_rx_priv);
	if (!fb_priv)
		goto err;

	if (unlikely((tmp_rx_lock = kzalloc(sizeof(rwlock_t), GFP_ATOMIC)) == NULL))
		goto err0;

	if (unlikely((tmp_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL))
		goto err1;

	if (unlikely((expected_seq_nr = kzalloc(sizeof(unsigned char), GFP_ATOMIC)) == NULL))
		goto err1a;
	
	rwlock_init(tmp_rx_lock);

	*expected_seq_nr = 1;
	
	skb_queue_head_init(tmp_list);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_crr_rx_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		//rwlock_init(&fb_priv_cpu->rx_lock);
		fb_priv_cpu->rx_lock = tmp_rx_lock;		
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->rx_seq_nr = expected_seq_nr;
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
	printk(KERN_ERR "[CRR_RX] Initialization passed!\n");
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	kfree(expected_seq_nr);
err1a:
	kfree(tmp_list);
err1:
	kfree(tmp_rx_lock);
	
err0:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	printk(KERN_ERR "[CRR_RX] Initialization failed!\n");
	return NULL;
}

static void fb_crr_rx_dtor(struct fblock *fb)
{
	int i, queue_len;
	struct sk_buff *skb_last;
	struct fb_crr_rx_priv *fb_priv_cpu;
	struct fb_crr_rx_priv __percpu *fb_priv;
	printk(KERN_ERR "[CRR_RX] Deinitialization 1!\n");

	rcu_read_lock();
	fb_priv = (struct fb_crr_rx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	/* CPUs share same priv. d */
	rcu_read_unlock();
	printk(KERN_ERR "[CRR_RX] Deinitialization 2!\n");

	write_lock(fb_priv_cpu->rx_lock);					// LOCK
	queue_len = skb_queue_len(fb_priv_cpu->list);
	printk(KERN_ERR "[CRR_RX] Deinitialization Qlen: %d!\n", queue_len);
	for (i = 0; i < queue_len; i++) {
		skb_last = skb_dequeue(fb_priv_cpu->list);
		kfree(skb_last);
	}
	kfree(fb_priv_cpu->list);
	kfree(fb_priv_cpu->rx_seq_nr);
	write_unlock(fb_priv_cpu->rx_lock);					// UNLOCK

	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
	printk(KERN_ERR "[CRR_RX] Deinitialization passed!\n");
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
