#define DRV_NAME		"ubridge"
#define DRV_VERSION		"0.1"
#define DRV_DESCRIPTION	"Tiny bridge driver"
#define DRV_COPYRIGHT	"(C) 2012 NDM Systems Inc. <ap@ndmsystems.com>"

#define UBRIDGE_MINOR	201


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

#define BR_PORT_BITS	10
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

static int cur_port = BR_MAX_PORTS - 1;
 /*
typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;
 */

static LIST_HEAD(ubr_list);

struct ubr_private {
	struct net_device		*master_dev;
	struct net_device_stats	stats;
	struct list_head		list;
	struct net_device		*dev;
	uint16_t				portno;
};

static struct sk_buff *ubr_handle_frame(struct sk_buff *skb)
{
	struct ubr_private *ubr, *tmp;

//	printk(KERN_ERR"handler(id=%d/0x%x): port_no=%d %d bytes\n",p->port_id,skb->protocol,p->port_no,skb->len);

	list_for_each_entry_safe(ubr, tmp, &ubr_list, list) {
		if (skb->dev == ubr->master_dev) {
			skb->dev = ubr->dev;
			skb->pkt_type = PACKET_HOST;
			ubr->dev->last_rx = jiffies;

			ubr->stats.rx_packets++;
			ubr->stats.rx_bytes += skb->len;
			dst_release(skb_dst(skb));
			skb_dst_set(skb, NULL);

			netif_receive_skb(skb);
			return NULL;
		}
	}
	return NULL;

}


static int ubr_open(struct net_device *tx_dev)
{
	netif_start_queue(tx_dev);
	return 0;
}

static int ubr_stop(struct net_device *tx_dev)
{
	struct ubr_private *tx_info = netdev_priv(tx_dev);
	struct net_device *master_dev = tx_info->master_dev;
	netif_stop_queue(tx_dev);
	if (netif_carrier_ok(tx_dev)) {
		netif_carrier_off(tx_dev);
		netif_carrier_off(master_dev);
	}
	return 0;
}

static int ubr_xmit(struct sk_buff *skb, struct net_device *tx_dev)
{
	struct ubr_private *ubr_tx = netdev_priv(tx_dev);
	struct net_device *master_dev = ubr_tx->master_dev;
	
	if (!master_dev)
		return -ENOTCONN;
	
	ubr_tx->stats.tx_packets++;
	ubr_tx->stats.tx_bytes += skb->len;

	skb->dev = master_dev;
	dev_queue_xmit(skb);

	return 0;
}

static struct net_device_stats *ubr_getstats(struct net_device *dev)
{
	struct ubr_private *info = netdev_priv(dev);
	return &info->stats;
}

static const struct net_device_ops ubr_netdev_ops =
{
	.ndo_open = ubr_open,
	.ndo_stop = ubr_stop,
	.ndo_start_xmit = ubr_xmit,
	.ndo_get_stats = ubr_getstats,
};

static int ubr_noget(char *buffer, struct kernel_param *kp)
{
	return 0;
}

static int ubr_deregister(struct net_device *dev)
{
	struct ubr_private *ubr= netdev_priv(dev);
	struct net_bridge_port *p; 
	
	dev_close(dev);
	
	if (!list_empty(&ubr->list))
		list_del_init(&ubr->list);
	
	if (ubr->master_dev) {
		p = br_port_get_rcu(ubr->master_dev);
		rcu_assign_pointer(ubr->master_dev->rx_handler_data, NULL);
		kobject_del(&p->kobj);
	}
	unregister_netdevice(dev);
	return 0;
}

static int ubr_alloc_master(const char *name)
{
	struct net_device *dev;
	struct ubr_private *ubr;
	int err;
	
	dev = alloc_netdev(sizeof(struct ubr_private), name, ether_setup);
	if (!dev)
		return -ENOMEM;
	
	ubr = netdev_priv(dev);
	ubr->dev = dev;

	random_ether_addr(dev->dev_addr);
	
	dev->tx_queue_len	= 0; /* A queue is silly for a loopback device */
	dev->features		= NETIF_F_FRAGLIST
						| NETIF_F_HIGHDMA
						| NETIF_F_LLTX;
	dev->flags		= IFF_BROADCAST | IFF_MULTICAST |IFF_PROMISC;
	dev->netdev_ops = &ubr_netdev_ops;
	dev->destructor		= free_netdev;

	err = register_netdev(dev);
	if (err) {
		free_netdev(dev);
		dev = ERR_PTR(err);
		goto out;
	}
	
	netif_carrier_off(dev);

	rtnl_lock();
	list_add(&ubr->list, &ubr_list);
	rtnl_unlock();
	
out:
	return 0;	
}

static int ubr_atto_master(const char *master,const char *slave)
{
	struct net_device *dev0, *dev1;
	struct ubr_private *ubr0;
	struct net_bridge_port *p;
	int err = -ENODEV;
	
	rtnl_lock();
	dev0 = __dev_get_by_name(&init_net, master);
	dev1 = __dev_get_by_name(&init_net, slave);
	rtnl_unlock();
	
	if ((!dev0) || (!dev1))
		goto out;
		
	memcpy(dev0->dev_addr,dev1->dev_addr,ETH_ALEN);
	ubr0 = netdev_priv(dev0);
	ubr0->master_dev = dev1;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;
	p->port_id = cur_port--;
	p->port_no = 0;
	p->state = BR_STATE_DISABLED;
	p->dev = dev1;
	rcu_assign_pointer(dev1->rx_handler_data, p);
	netif_carrier_on(dev0);
	return 0;

out:
	return err;
}

static int ubr_detach(const char *master,const char *slave)
{
	struct net_device *dev0, *dev1;
	struct ubr_private *ubr0;
	int err = -ENODEV;

	rtnl_lock();
	dev0 = __dev_get_by_name(&init_net, master);
	dev1 = __dev_get_by_name(&init_net, slave);
	rtnl_unlock();

	if ((!dev0) || (!dev1))
		goto out;
	ubr0 = netdev_priv(dev0);
	ubr0->master_dev = NULL;

	rcu_assign_pointer(dev1->rx_handler_data, NULL);

out:
	return err;
}


static int ubr_newif(const char *val, struct kernel_param *kp)
{
	int len;
	char name[IFNAMSIZ];

	len = strlen(val);
	while (isspace(val[len - 1]))
		len--;
	strncpy(name, val, len);
	name[len] = '\0';
	return (ubr_alloc_master(name) != 0);
}

static int ubr_attachif(const char *val, struct kernel_param *kp)
{
	int len,len0,len1;
	const char *mid;
	char name0[IFNAMSIZ],name1[IFNAMSIZ];
	
	len = strlen(val);
	while (isspace(val[len - 1]))
		len--;

	/* Split the string into 2 names */
	mid = memchr(val, ',', len);
	if (!mid)
		return -EINVAL;

	/* Get the first device name */
	len0 = mid - val;
	if (len0 > sizeof(name0) - 1)
		len = sizeof(name0) - 1;
	strncpy(name0, val, len0);
	name0[len0] = '\0';

	/* And the second device name */
	len1 = len - (len0 + 1);
	if (len1 > sizeof(name1) - 1)
		len1 = sizeof(name1) - 1;
	strncpy(name1, mid + 1, len1);
	name1[len1] = '\0';
	
	return ubr_atto_master(name0,name1);
}

static int ubr_detachif(const char *val, struct kernel_param *kp)
{
	int len,len0,len1;
	const char *mid;
	char name0[IFNAMSIZ],name1[IFNAMSIZ];
	
	len = strlen(val);
	while (isspace(val[len - 1]))
		len--;

	/* Split the string into 2 names */
	mid = memchr(val, ',', len);
	if (!mid)
		return -EINVAL;

	/* Get the first device name */
	len0 = mid - val;
	if (len0 > sizeof(name0) - 1)
		len = sizeof(name0) - 1;
	strncpy(name0, val, len0);
	name0[len0] = '\0';

	/* And the second device name */
	len1 = len - (len0 + 1);
	if (len1 > sizeof(name1) - 1)
		len1 = sizeof(name1) - 1;
	strncpy(name1, mid + 1, len1);
	name1[len1] = '\0';
	
	return ubr_detach(name0,name1);
}

static int __init ubridge_init(void)
{
	rcu_assign_pointer(ubr_handle_frame_hook, ubr_handle_frame);
	printk(KERN_INFO "ubridge: %s, %s\n", DRV_DESCRIPTION, DRV_VERSION);	
	return 0;
}

static void __exit ubridge_exit(void)
{
	struct ubr_private *ubr, *tmp;

	rtnl_lock();
	list_for_each_entry_safe(ubr, tmp, &ubr_list, list) {
		ubr_deregister(ubr->dev);
	}
	rtnl_unlock();
	rcu_assign_pointer(ubr_handle_frame_hook, NULL);

	printk(KERN_INFO "ubridge: driver unloaded\n");
}

module_param_call(newif, ubr_newif, ubr_noget, NULL, S_IWUSR);
module_param_call(attachif, ubr_attachif, ubr_noget, NULL, S_IWUSR);
module_param_call(detachif, ubr_detachif, ubr_noget, NULL, S_IWUSR);
/*
module_param_call(delif, ubr_delif, ubr_noget, NULL, S_IWUSR);
*/
module_init(ubridge_init);
module_exit(ubridge_exit);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");

