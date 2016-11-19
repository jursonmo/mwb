
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/rculist.h>
#include <linux/list.h>
#include <net/net_namespace.h>
#include <linux/jhash.h>
#include <linux/version.h>

/*for auto route*/
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/ip_fib.h>
#include <net/rtnetlink.h>

#include <net/route.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define LE_NIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]	
	
#define MWB_LOG_LEVEL	2
#define MWB_LOG(level, fmt, ...) do { \
	if ((level) <= MWB_LOG_LEVEL) { \
		printk("*MWB* " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define MWB_LOG_IF(level, cond, fmt, ...) do { \
	if ((level) <= MWB_LOG_LEVEL) { \
		if (cond) { \
			printk("*MWB* " fmt "\n", ##__VA_ARGS__); \
		} \
	} \
} while (0)


#define MWB_ASSERT(cond)	BUG_ON(!(cond))

#define MWB_ASSERT_MSG(cond, fmt, ...) do { \
	if (unlikely(!(cond))) { \
		printk(fmt "\n", ##__VA_ARGS__); \
		BUG(); \
	} \
} while (0)


#define MWB_ERROR(...)			MWB_LOG(0, ##__VA_ARGS__)
#define MWB_ERROR_IF(cond, ...)	MWB_LOG_IF(0, cond, ##__VA_ARGS__)

#define MWB_WARN(...)			MWB_LOG(1, ##__VA_ARGS__)
#define MWB_WARN_IF(cond, ...)	MWB_LOG_IF(1, cond, ##__VA_ARGS__)

#define MWB_INFO(...)			MWB_LOG(2, ##__VA_ARGS__)
#define MWB_INFO_IF(cond, ...)	MWB_LOG_IF(2, cond, ##__VA_ARGS__)

#define MWB_DEBUG(...)			MWB_LOG(3, ##__VA_ARGS__)
#define MWB_DEBUG_IF(cond, ...)	MWB_LOG_IF(3, cond, ##__VA_ARGS__)

#define MWB_LINE_MASK_CHECK(mask, i)	(mask & (1u << i))
#define MWB_LINE_MASK_SET(mask, i)	((void)(mask |= 1u << i))
#define MWB_LINE_MASK_CLR(mask, i)	((void)(mask &= ~(1u << i)))
#define MWB_LINE_MASK_FOR_EACH(i, mask) \
	for ( ; (i = __builtin_ffs(mask) - 1) != -1; MWB_LINE_MASK_CLR(mask, i))

struct pair_info{
	char sip[20];
	char dip[20];
	unsigned int mark;
	char dst_dev[2][20];
}g_pair_info;
#define MLINES_MAX	(8)
//每秒计算流量次数64*16=16*4*16=1024, COUNT_TIMES * 4 *MWB_RATE_CHECK_INTVL
#define COUNT_TIMES (64)
//产生流量估计需要的时间ms
#define MWB_RATE_CHECK_INTVL 16
//定期检查entry 是否超时间隔
#define CHECK_ENTRY_INTVL (2*60*HZ)
#define MWB_MAX_CHECK_ENTRY 256
//没有连接引用后,超时期限
#define MWB_ENTRY_TIMEOUT_MAX (10*HZ)
#define DEV_NAME_SIZE 20
struct mwb_cpu_dev_stats {
    u64         rx_bytes;
    u64         tx_bytes;
    struct u64_stats_sync   syncp;
};
struct line_info_st{	
	uint8_t mark;	
	char dev_name[DEV_NAME_SIZE];
	struct net_device *dev;
	struct mwb_cpu_dev_stats __percpu *stats;
	unsigned long down_bandwidth;
	unsigned long up_bandwidth;
	unsigned long n;
	u64 down_bytes;
	unsigned int down[COUNT_TIMES];
	u64 up_bytes;
	unsigned int up[COUNT_TIMES];
	unsigned int up_rate;
	unsigned int down_rate;
};

struct mwb_mline_st {
	uint8_t type;
	uint8_t line_mask; 
	uint8_t line_alive_cnt;
	spinlock_t line_lock;
	struct timer_list timer;
	unsigned long timestamp;
	atomic_t last_chose_line_id;
	struct line_info_st line_info[MLINES_MAX];	//0x1, 2, 3
};
#define  MLINES_NONE (0)
struct mwb_mline_st  mwb_lines;
uint8_t mwb_type = MLINES_NONE;
unsigned long g_line_change_jiffies = 0;
struct mwb_key_info{
	unsigned int ipsaddr;
	unsigned int ipdaddr;
};
struct mwb_entry{
	struct hlist_node	hlist;
	struct list_head ct_list;
	spinlock_t ct_list_lock;
	struct rcu_head rcu;
	int deleted;
	atomic_t refcnt;
	struct mwb_key_info mki;
	unsigned int mark;
	unsigned long timestamp;
	unsigned long dst[IP_CT_DIR_MAX];
	spinlock_t dst_lock[IP_CT_DIR_MAX];
	uint8_t line_mask;
};
typedef int (*match_keys)( struct mwb_key_info *mki1, struct mwb_key_info *mki2);
#define MWB_HASH_SIZE 2048
struct ht_table {
	struct hlist_head hhead;
	spinlock_t lock;
};
struct HashTable{	
	struct ht_table  *table;
	int alloc_by_vmalloc;
	unsigned int hash_mask;
	unsigned int hash_salt;
	struct kmem_cache *hcache;
	int (*node_hash_key)(struct mwb_key_info *mki);
	match_keys node_match_key;
	spinlock_t  lock;
	struct timer_list ktimer;
	atomic_t counter;
	unsigned int entry_timeout;
	unsigned int timer_max_check_cnt;
	unsigned int timer_slot_check;
	unsigned int timer_check_intvl;
};
struct HashTable *mwbHashTable = NULL;

#define LOADPOLICY_MARK 0x10
struct load_policy_t {
	struct list_head mask_list;
	unsigned int hash_salt;
	unsigned int cnt;
	spinlock_t lp_lock;
};
struct load_policy_t LoadPolicy;
#define LP_HASH_SIZE 32
struct load_policy_list_node {
	struct list_head list;
	struct rcu_head rcu;
	//unsigned int mask_len;
	unsigned int mask;
	unsigned int hlist_node_cnt;
	struct hlist_head table[LP_HASH_SIZE];
};
struct load_policy_hlist_node {
	struct hlist_node hlist;
	unsigned int network;
	unsigned int mark;
	struct rcu_head rcu;
};
static int lp_add_network(unsigned int network, unsigned int mask, unsigned int mark);
static int lp_del_network(unsigned int network, unsigned int mask);

static void mwb_entry_timeout_check(unsigned long data);
static unsigned int mwb_hash_salt(void);
static unsigned int mwb_ht_mask(void);
void me_ct_attach(struct nf_conn *ct, struct mwb_entry *me);
static int mwb_rate_handle(void);

static int mwb_iprule_del(int line_no);
static int mwb_iprule_set(int line_no);

static inline struct dst_entry *mwb_entry_dst(struct mwb_entry *me, int dir);

static inline bool ipv4_is_lgroup(__be32 addr)
{
	return (addr & htonl(0x000000ff)) == htonl(0x000000ff);
}

int mwb_hash1(struct mwb_key_info *mki)
{
	return jhash_1word(mki->ipsaddr, mwb_hash_salt()) & mwb_ht_mask();
}
int mwb_hash2(struct mwb_key_info *mki)
{
	return jhash_2words(mki->ipsaddr, mki->ipdaddr, mwb_hash_salt()) & mwb_ht_mask();
}
int mwb_match_key1(struct mwb_key_info *mki1, struct mwb_key_info *mki2)
{
	return mki1->ipsaddr == mki2->ipsaddr ;
}
int mwb_match_key2(struct mwb_key_info *mki1, struct mwb_key_info *mki2)
{
	return ((mki1->ipdaddr ^ mki2->ipdaddr) | (mki1->ipsaddr ^ mki2->ipsaddr) ) == 0;
}
void ht_tbpool_destroy(struct HashTable *ht)
{
	if(ht->alloc_by_vmalloc)
		vfree(ht->table);
	else
		kfree(ht->table);
}
	
static int  ht_tbpool_create(struct HashTable *ht, int slot_num)
{
	uint32_t size = sizeof(*ht->table) * slot_num;
	int i;

	if(size <= KMALLOC_MAX_SIZE) {
	    ht->table = kmalloc(size, GFP_KERNEL);
	    ht->alloc_by_vmalloc = 0;
	} else {
	    ht->table = vmalloc(size);
	    ht->alloc_by_vmalloc = 1;
	}
	if(!ht->table)	{
		MWB_ERROR("slot_num=%d,size=%u,ht_tbpool_create fail", slot_num, size);
		return -1;
	}
	memset(ht->table, 0, size);
	for (i = 0; i < slot_num; i++){
		INIT_HLIST_HEAD(&ht->table[i].hhead);	
		spin_lock_init(&ht->table[i].lock);
	}
	MWB_INFO("slot_num=%d,size=%u,ht_tbpool_create success", slot_num, size);
	return 0;
}
static struct HashTable *mwb_ht_init(void){
	int slot_num;
	struct HashTable *ht = NULL;
	ht = (struct HashTable *)kzalloc(sizeof(struct HashTable), GFP_ATOMIC);
	if (!ht){
		MWB_ERROR(" mwbHashTable kzalloc fail");
		return NULL;
	}
	slot_num = rounddown_pow_of_two(MWB_HASH_SIZE);
	ht->hash_mask = slot_num -1;
	if(ht_tbpool_create(ht, slot_num))
		return NULL;
	get_random_bytes(&ht->hash_salt, sizeof(ht->hash_salt));

	ht->hcache = kmem_cache_create("mwb_hcache", sizeof(struct mwb_entry), 0, 
										SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	if(!ht->hcache){
		MWB_ERROR("kmem_cache_create fail \n");
		ht_tbpool_destroy(ht);
		return NULL;
	}
		
	atomic_set(&ht->counter, 0);
	spin_lock_init(&ht->lock);
	ht->node_hash_key = mwb_hash2;
	ht->node_match_key = mwb_match_key2;
	ht->timer_max_check_cnt = MWB_MAX_CHECK_ENTRY;
	ht->timer_slot_check = 0;
	ht->entry_timeout = MWB_ENTRY_TIMEOUT_MAX;
	ht->timer_check_intvl = CHECK_ENTRY_INTVL;

	setup_timer(&ht->ktimer, mwb_entry_timeout_check,  (unsigned long)ht);
	mod_timer(&ht->ktimer, jiffies + ht->entry_timeout);	
	return ht;
}
static inline void mwb_lock(void)
{
	spin_lock(&mwbHashTable->lock);
}
static inline void mwb_unlock(void)
{
	spin_unlock(&mwbHashTable->lock);
}
static inline void mwb_ht_head_lock(struct hlist_head *head)
{
	struct ht_table *tb = (struct ht_table *)head;
	spin_lock(&tb->lock);
}
void mwb_ht_head_unlock(struct hlist_head *head)
{
	struct ht_table *tb = (struct ht_table *)head;
	spin_unlock(&tb->lock);
}

static inline void mwb_ht_inc(void)
{
	atomic_inc(&mwbHashTable->counter);
}
static inline void mwb_ht_dec(void)
{
	atomic_dec(&mwbHashTable->counter);
}

static inline void *mwb_malloc(int size)
{
	return kmem_cache_alloc(mwbHashTable->hcache, GFP_ATOMIC);
}
static void mwb_free(void *p)
{
	if(p){
		kmem_cache_free(mwbHashTable->hcache, p);
		mwb_ht_dec();
	}
}

static inline unsigned int mwb_ht_mask(void)
{
	return mwbHashTable->hash_mask;
}
static inline unsigned int mwb_hash_salt(void)
{
	return mwbHashTable->hash_salt;
}
static inline int mwb_hash(struct mwb_key_info *mki){
	return mwbHashTable->node_hash_key(mki);
}
static struct hlist_head *hash_head_get(struct mwb_key_info *mki)
{
	int hash_index = mwb_hash(mki);
	return &mwbHashTable->table[hash_index].hhead;
}
static inline int mwb_entry_match(struct mwb_key_info *mki1, struct mwb_key_info *mki2)
{
	return mwbHashTable->node_match_key(mki1, mki2);
}

struct mwb_entry *mwb_entry_each_match(struct hlist_head *h, struct mwb_key_info *mki)
{
	struct mwb_entry *entry;
	hlist_for_each_entry_rcu(entry, h, hlist){
		if(mwb_entry_match(&entry->mki, mki))
			return entry;
	}
	return NULL;
}
struct mwb_entry *mwb_entry_find(struct mwb_key_info *mki)
{
	struct hlist_head *h = hash_head_get(mki);
	return mwb_entry_each_match(h, mki);
}
static struct mwb_entry *mwb_entry_create(void)
{
	struct mwb_entry *entry = NULL;
	entry = mwb_malloc(sizeof(*entry));
	if (!entry){
		MWB_WARN("wmb_malloc memory fail");
		return NULL;
	}
	mwb_ht_inc();
	memset(entry, 0, sizeof(struct mwb_entry));
	atomic_set(&entry->refcnt, 0);
	INIT_HLIST_NODE(&entry->hlist);
	INIT_LIST_HEAD(&entry->ct_list);
	spin_lock_init(&entry->ct_list_lock);
	spin_lock_init(&entry->dst_lock[IP_CT_DIR_ORIGINAL]);
	spin_lock_init(&entry->dst_lock[IP_CT_DIR_REPLY]);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,36))
	init_rcu_head(&entry->rcu);
#else
	INIT_RCU_HEAD(&entry->rcu);
#endif
	entry->timestamp = jiffies;
	return entry;
}
static struct mwb_entry *mwb_entry_add(struct mwb_key_info *mki, struct sk_buff *skb)
{
	struct hlist_head *h;
	struct mwb_entry *entry = NULL, *me = NULL;
	MWB_ASSERT(skb->mark);
	MWB_ASSERT(mki);
	if(!(entry = mwb_entry_create()))
		return NULL;
	
	entry->mki = *mki;
	entry->mark = skb->mark;

	h = hash_head_get(mki);
	mwb_ht_head_lock(h);	
	if((me = mwb_entry_each_match(h, mki))){
		mwb_free(entry);	
		mwb_ht_head_unlock(h);
		skb->mark = me->mark;
		/*the same pair of sip and dip, but not the same ct , so this ct should be marked and attach, return me for sure*/
		((struct nf_conn *)skb->nfct)->mark = me->mark;
		//MWB_INFO("entry exist , mwb_entry_add return");
		return me;
	}		
	hlist_add_head_rcu(&entry->hlist, h);	
	mwb_ht_head_unlock(h);
	return entry;
}
static inline void mwb_entry_dst_drop(struct mwb_entry *me, int dir)
{
	if (me->dst[dir]) {
		refdst_drop(me->dst[dir]);
		me->dst[dir] = 0UL;
	}
}
static void mwb_entry_dst_drop_all(struct mwb_entry *me)
{
	mwb_entry_dst_drop(me, IP_CT_DIR_ORIGINAL);
	mwb_entry_dst_drop(me, IP_CT_DIR_REPLY);
}
static void mwb_entry_free(struct rcu_head *rh)
{
	struct mwb_entry *e = container_of(rh, struct mwb_entry, rcu);
	mwb_entry_dst_drop_all(e);
	mwb_free(e);
}

static void mwb_entry_detach_all_ct(struct mwb_entry *entry)
{
	struct nf_conn *ct,*tmp;
	list_for_each_entry_safe(ct, tmp, &entry->ct_list, list){
		/*TODO: 
				if ct has free, here may be dangerous , so have to spin_lock to make sure  list_del_init correct, 
				and then rcu_assign_pointer(mwb_ct_detach, NULL)
		*/
		list_del_init(&ct->list);
		atomic_dec(&entry->refcnt);
		ct->mwb_entry = NULL;
	}
}

 static void mwb_entry_del(struct hlist_head *h, struct mwb_entry *entry)
{	
	mwb_ht_head_lock(h);
	/* 目前只有timer 一个地方有删除操作,暂时不需要判断deleted
	if (entry->deleted){
		mwb_ht_head_unlock(h);
		return;
	}
	entry->deleted = 1;
	*/
	hlist_del_rcu(&entry->hlist);					
	mwb_ht_head_unlock(h);
	
	/*here , maybe ct just attach entry this moment, so detach ct*/
	spin_lock(&entry->ct_list_lock);
	mwb_entry_detach_all_ct(entry);
	/*set deleted flag, make sure ct cannot attch this entry*/
	entry->deleted = 1;
	spin_unlock(&entry->ct_list_lock);
	/*here, entry->refcnt==0  is certainly*/
	MWB_ASSERT(atomic_read(&entry->refcnt) == 0);	
	
	call_rcu(&entry->rcu, mwb_entry_free);	
}
static void mwb_entry_timeout_check(unsigned long data)
{
	int i, checked_cnt = 0, jiffies_intvl;
	unsigned int check_times_around;
	//unsigned long jiffies_fly;
	struct mwb_entry *entry;
	struct HashTable *ht = (struct HashTable *)data;
	rcu_read_lock();
	for (i = ht->timer_slot_check & ht->hash_mask; i < ht->hash_mask + 1; i++){
		hlist_for_each_entry_rcu(entry, &ht->table[i].hhead, hlist){
			/*
			jiffies_fly = jiffies - entry->timestamp;
			if(jiffies_fly > ht->entry_timeout){
				mwb_entry_del(&ht->table[i].hhead, entry);
			}
			*/
			if(atomic_read(&entry->refcnt) == 0 && time_after(jiffies, entry->timestamp + ht->entry_timeout)){
				mwb_entry_del(&ht->table[i].hhead, entry);
			}
			checked_cnt++;
		}
		ht->timer_slot_check = i + 1;
		if(checked_cnt >= ht->timer_max_check_cnt)
			break;
	}
	rcu_read_unlock();
	//TODO:
	check_times_around = (atomic_read(&ht->counter) + ht->timer_max_check_cnt -1)/ht->timer_max_check_cnt;
	if (!check_times_around)
		check_times_around =  1;
	MWB_INFO("----ht->counter=%d, hash_size=%u, max_check_cnt=%u, check_times_around=%d, timer_check_intvl=%u ,entry_timeout=%ds-----", 
			atomic_read(&ht->counter), ht->hash_mask+1, ht->timer_max_check_cnt, check_times_around, ht->timer_check_intvl/HZ, ht->entry_timeout/HZ);
	if(ht->timer_slot_check == ht->hash_mask+1)
		MWB_INFO("\n-----------------check around  over--------------------\n");
	jiffies_intvl = ht->timer_check_intvl/check_times_around;
	mod_timer(&ht->ktimer, jiffies + (jiffies_intvl>10?jiffies_intvl:10));
}

 /* make sure mwb_hook_fn and ct can not reference entry any more*/
 void hash_table_cleanup(struct HashTable *ht){
	int i;
	struct mwb_entry *entry;
	struct hlist_node *n;
	for (i = 0; i < ht->hash_mask + 1; i++){
		hlist_for_each_entry_safe(entry, n, &ht->table[i].hhead, hlist){
			hlist_del_init(&entry->hlist);
			spin_lock_bh(&entry->ct_list_lock);
			mwb_entry_detach_all_ct(entry);
			spin_unlock_bh(&entry->ct_list_lock);
			MWB_ASSERT(atomic_read(&entry->refcnt) == 0);	
			//mwb_free(entry);
			call_rcu(&entry->rcu, mwb_entry_free);/*1. maybe ct also reference this entry, 2. need to drop dst*/
		}
	}
}

static unsigned int mwb_get_dev_rate(unsigned int *arry)
{
	int i;
	unsigned int rate = 0;
	for(i = 0; i < COUNT_TIMES; i++){
		rate += arry[i];
	}
	return rate;
}

static unsigned int mwb_chose_routine_by_traffic(void)
{
	int i, lid = 0, min_up_id = 0;
	unsigned int min_down_occup_rate = ~0u, down_occup_rate/*, down_rate = 0*/;
	unsigned int min_up_occup_rate = ~0u, up_occup_rate/*, up_rate = 0*/;
	struct line_info_st *li;
	uint8_t mask = mwb_lines.line_mask;	
	if(time_after(jiffies, mwb_lines.timestamp + (MWB_RATE_CHECK_INTVL >> 1))){
		mwb_lines.timestamp = jiffies;
	CHECK_ALL_LINE_RATE:
		MWB_LINE_MASK_FOR_EACH(i, mask){
			li = &mwb_lines.line_info[i];
			//down_rate = mwb_get_dev_rate(li->down);
			if(!li->down_rate){
				lid = i;
				goto chose_it; 
			}
			
			//up_rate = mwb_get_dev_rate(li->up);
			up_occup_rate =  li->up_rate/li->down_bandwidth;
			if (up_occup_rate > 850){
				if (up_occup_rate < min_up_occup_rate){
					min_up_occup_rate = up_occup_rate;
					min_up_id = i;
				}
				continue;
			}

			down_occup_rate = li->down_rate/li->down_bandwidth;
			if( down_occup_rate < min_down_occup_rate){
				min_down_occup_rate = down_occup_rate;
				lid = i;
			}	
		}
		if (min_down_occup_rate == ~0u)
			lid = min_up_id;
	chose_it:
		atomic_set(&mwb_lines.last_chose_line_id, lid);
	}else{	
		lid = atomic_read(&mwb_lines.last_chose_line_id);
		if(!MWB_LINE_MASK_CHECK(mask, lid))
			goto CHECK_ALL_LINE_RATE;
		#if 0
		MWB_LINE_MASK_CLR(mask, lid);
		MWB_LINE_MASK_FOR_EACH(i, mask){
			li = &mwb_lines.line_info[i];
			//down_rate = mwb_get_dev_rate(li->down);
			if(!li->down_rate)
				lid = i;
		}
		#endif
	}
	return mwb_lines.line_info[lid].mark;
}
#if 0
/*
	dev_get_stats make a bug: 
	dev_get_stats -->ndo_get_stats64 = igb_get_stats64 ->spin_lock/spin_unlock,
	timer_fn will preempt when netlink handle igb_get_stats64 in a process context
*/
static struct mwb_dev_stat mwb_dev_stats_get(struct net_device **dev, char *devname)
{
	struct mwb_dev_stat mds;
	struct rtnl_link_stats64 stats;
	if (*dev){
		dev_get_stats(*dev, &stats);
	}else {
		*dev = dev_get_by_name(&init_net, devname);
		if (*dev){	
			dev_get_stats(*dev, &stats);
			dev_put(*dev);
		}
	}
	mds.rx_bytes = stats.rx_bytes;
	mds.tx_bytes = stats.tx_bytes;
	return mds;
}
#endif
static void mwb_stats_seqlock_init(struct mwb_cpu_dev_stats *stats)
{
	unsigned int cpu;
	struct mwb_cpu_dev_stats *s;
	if (!stats)
		return;
   	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats, cpu);
		u64_stats_init(s->syncp);		
	}
}
static struct mwb_cpu_dev_stats mwb_dev_stats_get(struct mwb_cpu_dev_stats *stats)
{
	struct mwb_cpu_dev_stats tmp, sum = {0};
	unsigned int cpu;
	if(!stats)
		return sum;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,36))
    	for_each_possible_cpu(cpu) {
		unsigned int start;
		const struct mwb_cpu_dev_stats *bstats = per_cpu_ptr(stats, cpu);
		do {
		    start = u64_stats_fetch_begin_irq(&bstats->syncp);
		    memcpy(&tmp, bstats, sizeof(tmp));
		} while (u64_stats_fetch_retry_irq(&bstats->syncp, start));
#else
	for_each_possible_cpu(cpu) {
		unsigned int start;
		const struct mwb_cpu_dev_stats *bstats = per_cpu_ptr(stats, cpu);
		do {
    			start = u64_stats_fetch_begin(&bstats->syncp);
    			memcpy(&tmp, bstats, sizeof(tmp));
		} while (u64_stats_fetch_retry(&bstats->syncp, start));
#endif
		sum.tx_bytes += tmp.tx_bytes;
		sum.rx_bytes += tmp.rx_bytes;
	}
	return sum;
}
static int mwb_rate_handle(void)
{
	int i, idx;
	struct mwb_cpu_dev_stats mds;
	struct line_info_st *li;
	uint8_t mask = mwb_lines.line_mask;
	spin_lock_bh(&mwb_lines.line_lock);// rcu_read_lock();	
	MWB_LINE_MASK_FOR_EACH(i, mask){
		li = &mwb_lines.line_info[i];
		mds = mwb_dev_stats_get(li->stats);

		idx = li->n & (COUNT_TIMES-1);
		li->down_rate -= li->down[idx];
		if (mds.rx_bytes > li->down_bytes){			
			li->down[idx] = mds.rx_bytes - li->down_bytes;
			li->down_rate += li->down[idx];

		}else{
			li->down[idx]=0;
		}
		li->up_rate -= li->up[idx];
		if (mds.tx_bytes > li->up_bytes){		
			li->up[idx] = mds.tx_bytes - li->up_bytes;
			li->up_rate += li->up[idx];
		}else{
			li->up[idx]=0;
		}
		li->n ++;
		li->down_bytes = mds.rx_bytes;
		li->up_bytes = mds.tx_bytes;
	}	
	spin_unlock_bh(&mwb_lines.line_lock);// rcu_read_unlock();	
	return 1;
}
 void mwb_rate_timer_fun(unsigned long data)
{
	#if 0
	if(time_after(jiffies, mwb_lines.timestamp + MWB_RATE_CHECK_INTVL))
		mwb_rate_handle();
	mod_timer(&mwb_lines.timer, jiffies + HZ/COUNT_TIMES);
	#endif
	mwb_rate_handle();
	mod_timer(&mwb_lines.timer, jiffies + 16);	
}
static void mwb_lines_init(void)
{
	memset(&mwb_lines, 0, sizeof(mwb_lines));	
	spin_lock_init(&mwb_lines.line_lock);
	setup_timer(&mwb_lines.timer, mwb_rate_timer_fun, 0);
	mwb_lines.timestamp = jiffies;
	atomic_set(&mwb_lines.last_chose_line_id, 0);
	mod_timer(&mwb_lines.timer, jiffies + 1);
}
int mwb_mlines_reset(int line_no, int line_alive, char *line_devname , unsigned int line_down_bw, unsigned int line_up_bw)
{
	struct mwb_cpu_dev_stats __percpu *stats_free = NULL;
	struct line_info_st  *li;
	if(line_no <0 || line_no > MLINES_MAX-1){
		printk("line_no =%d out of range [0-%d]\n", line_no, MLINES_MAX-1);
		return 0;
	}
	
	spin_lock_bh(&mwb_lines.line_lock);
	li = &mwb_lines.line_info[line_no];
	if (!line_alive){
		if (MWB_LINE_MASK_CHECK(mwb_lines.line_mask, line_no)){
			mwb_lines.line_alive_cnt--;
			MWB_LINE_MASK_CLR(mwb_lines.line_mask, line_no);
			stats_free = li->stats;
			//li->stats = NULL;
			memset(li, 0, sizeof(struct line_info_st));	
			mwb_iprule_del(line_no);
		}
		goto out;		
	}
		
	li->mark = line_no + 1;
	li->down_bandwidth = line_down_bw;
	li->up_bandwidth = line_up_bw;
	li->n = 0;
	memset(li->up, 0, sizeof(li->up));
	memset(li->down, 0, sizeof(li->down));
	li->up_rate = 0;
	li->down_rate = 0;
	if(strlen(line_devname)){
		memset(li->dev_name, 0 ,sizeof(li->dev_name));
		strncpy(li->dev_name, line_devname, DEV_NAME_SIZE-1);
		li->dev_name[DEV_NAME_SIZE-1] = '\0';
	}
	li->dev = dev_get_by_name(&init_net, li->dev_name);
	if (!li->dev){
		MWB_WARN("dev_get_by_name %s fail", li->dev_name);
		goto out;
	}
	dev_put(li->dev);
	stats_free = li->stats;
	li->stats = alloc_percpu(struct mwb_cpu_dev_stats);
	if(!li->stats){
		MWB_WARN("alloc_percpu stats %s fail", li->dev_name);
		goto out;
	}
	mwb_stats_seqlock_init(li->stats);
	if (MWB_LINE_MASK_CHECK(mwb_lines.line_mask, line_no))
		goto out;	
	MWB_LINE_MASK_SET(mwb_lines.line_mask, line_no);
	mwb_iprule_set(line_no);
	mwb_lines.line_alive_cnt++;
	g_line_change_jiffies = jiffies;
out:	
	spin_unlock_bh(&mwb_lines.line_lock);
	if(stats_free){
		synchronize_net();
		free_percpu(stats_free);
	}
	return 0;
}

static ssize_t mline_sysfs_attr_show(
	struct module_attribute *mattr,
	struct module_kobject *mod,
	char *buf)
{
	int i, th = 0;
	ssize_t ret = 0;
	struct line_info_st *li;
	uint8_t mask = mwb_lines.line_mask;
	struct load_policy_list_node *pos, *tmp;
	struct load_policy_hlist_node *net_entry;
	struct hlist_node *n;
	
	ret = sprintf(buf, "last find:sip=%s, dip=%s, mark=%u, dst_dev =(%s)->(%s) \n", g_pair_info.sip, g_pair_info.dip, g_pair_info.mark, g_pair_info.dst_dev[0], g_pair_info.dst_dev[1]);
	ret += sprintf(buf + ret, "[type:%d] [line_flag:%02x][live_cnt:%d]\n", mwb_lines.type, mwb_lines.line_mask, mwb_lines.line_alive_cnt);

	MWB_LINE_MASK_FOR_EACH(i, mask){
		li = &mwb_lines.line_info[i];
		ret += sprintf(buf + ret, "\t i =%d, mark=%x, devname=%s, down_bw=%luKB, up_bw=%luKB, down_rate =%u,%u bytes,  up_rate =%u,%u bytes\n", i
					, li->mark, li->dev_name, li->down_bandwidth, li->up_bandwidth, li->down_rate, mwb_get_dev_rate(li->down), li->up_rate, mwb_get_dev_rate(li->up));
	}
	ret += sprintf(buf + ret, "=======network cnt=%u============\n", LoadPolicy.cnt);
	list_for_each_entry_safe(pos, tmp, &LoadPolicy.mask_list, list){
		for (i = 0; i < sizeof(pos->table)/sizeof(pos->table[0]); i++){
			hlist_for_each_entry_safe(net_entry, n, &pos->table[i], hlist){
				ret += sprintf(buf + ret, "%d(hash_id=%d)\t%u.%u.%u.%u/%u.%u.%u.%u\tmark=%u\n", ++th, i
					, LE_NIPQUAD(net_entry->network), LE_NIPQUAD(pos->mask), net_entry->mark);
			}
		}
		ret += sprintf(buf + ret, "------------------\n");
	}	
	return ret;
}
static int ip_str_to_num(const char *ipstr, unsigned int *ip)
{
	unsigned int a,b,c,d;
	char tmp;

	if (sscanf(ipstr, "%u.%u.%u.%u %c", &a, &b, &c, &d, &tmp) != 4 ||
		a > 255 || b > 255 || c > 255 || d > 255) {
		*ip = 0;
		return -1;
	}

	*ip = (a << 24) | (b << 16) | (c << 8) | d;
	return 0;
}
static ssize_t mline_sysfs_attr_store(
	struct module_attribute *mattr,
	struct module_kobject *mod,
	const char *buf,
	size_t count)
{
	int line_no, line_alive, mark, type;
	unsigned int line_down_bw, line_up_bw;
	char line_devname[20];
	char nw_op[8];
	char network_str[20], sip_str[20], dip_str[20];
	char mask_str[20];
	char tmp;
	unsigned int network, mask, sip, dip;
	struct mwb_key_info mki;
	struct mwb_entry *me;
	memset(line_devname, 0, sizeof(line_devname));
	memset(network_str, 0, sizeof(network_str));
	memset(mask_str, 0, sizeof(mask_str));
	//"line_no,line_alive,devname, daikuan; ; ; ;"
	printk("count =%lu ,buf = %s \n", count, buf);
	if (strncmp(buf,  "type", strlen("type")) == 0){
		if(sscanf(buf, "type %d %c", &type, &tmp) != 1){
			MWB_ERROR("like: type 1");
			return count;
		}
		mwb_lines.type = type;
		return count;
	}
	if (strncmp(buf,  "find", strlen("find")) == 0){
		memset(sip_str, 0, sizeof(sip_str));
		memset(dip_str, 0, sizeof(dip_str));
		if(sscanf(buf, "find %s %s %c", sip_str, dip_str, &tmp) != 2){
			MWB_ERROR("error :find sip = %s , dip=%s", sip_str, dip_str);
			MWB_ERROR("like: find 192.168.1.2 8.8.8.8");
			return count;
		}
		if(ip_str_to_num(sip_str, &sip) || ip_str_to_num(dip_str, &dip)){
			MWB_ERROR("error :find sip = %s , dip=%s", sip_str, dip_str);
			return count;
		}
		mki.ipsaddr = htonl(sip);
		mki.ipdaddr = htonl(dip);
		memset(&g_pair_info, 0, sizeof(g_pair_info));
		rcu_read_lock();
		me = mwb_entry_find(&mki);
		if (me){
			g_pair_info.mark = me->mark;			
			if(mwb_entry_dst(me, 0))
				strcpy(g_pair_info.dst_dev[0], mwb_entry_dst(me, 0)->dev->name);
			if(mwb_entry_dst(me, 1))
				strcpy(g_pair_info.dst_dev[1], mwb_entry_dst(me, 1)->dev->name);
			MWB_INFO("yes find %s -> %s ,mark =%u, dev: (%s) ->(%s) .", sip_str, dip_str, me->mark, g_pair_info.dst_dev[0], g_pair_info.dst_dev[1]);
				
		}
		rcu_read_unlock();
		strcpy(g_pair_info.sip, sip_str);
		strcpy(g_pair_info.dip, dip_str);
		return count;
	}
	if (strncmp(buf,  "network", strlen("network")) == 0){
		/*like: network [add|del] 192.168.1.0 255.255.255.0*/
		if(sscanf(buf, "network %s %s %s %d %c", nw_op, network_str, mask_str, &mark, &tmp) != 4){
			MWB_ERROR("nw_op =%s, network_str=%s, mask_str=%s, mark=%d", nw_op, network_str, mask_str, mark);
			MWB_ERROR("like: network [add|del] 192.168.1.0 255.255.255.0 1");
			return count;
		}
			
		if(ip_str_to_num(network_str, &network) || ip_str_to_num(mask_str, &mask) || mark <1 || mark > MLINES_MAX){
			MWB_ERROR("nw_op =%s, network_str=%s, mask_str=%s, mark=%d", nw_op, network_str, mask_str, mark);
			return count;
		}else{
			if(((mask-1) | mask) != 0xFFFFFFFF){
        			MWB_ERROR("it is invalidate mask_str =%s, mask=%u\n", mask_str, mask);
				return count;
			}
			spin_lock(&LoadPolicy.lp_lock);
			if (strcmp(nw_op, "add") == 0)
				lp_add_network(network, mask, mark|LOADPOLICY_MARK);
			else if (strcmp(nw_op, "del") == 0)
				lp_del_network(network, mask);
			else
				MWB_ERROR("nw_op =%s, must be 'add' or 'del' ", nw_op);
			spin_unlock(&LoadPolicy.lp_lock);
		}		
	}else{
		sscanf(buf, "%d %d %19s %u %u", &line_no, &line_alive, line_devname, &line_down_bw, &line_up_bw);
		printk("kernel :%d,%d,%s,%u,%u\n", line_no, line_alive, line_devname, line_down_bw, line_up_bw);
		mwb_mlines_reset(line_no, line_alive, line_devname ,line_down_bw, line_up_bw);
	}
	return count;
}

static struct module_attribute mline_sysfs_attr =
	__ATTR(mline, 0644, mline_sysfs_attr_show, mline_sysfs_attr_store);

static int mline_sysfs_register(void)
{
	return sysfs_create_file(&THIS_MODULE->mkobj.kobj, &mline_sysfs_attr.attr);
	
}
static void mline_sysfs_unregister(void)
{
	return sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &mline_sysfs_attr.attr);
	
}
static inline unsigned int check_line_alive_by_mark(unsigned int  mark)
{
	MWB_ASSERT(mark);
	return mwb_lines.line_mask & (1u << (mark-1));
}

static void mwb_key_info_get(struct sk_buff *skb, struct mwb_key_info *mki)
{
	struct iphdr *iph;
	iph = ip_hdr(skb);
	mki->ipsaddr = iph->saddr;
	mki->ipdaddr = iph->daddr;
}
static void LoadPolicy_init(void)
{
	INIT_LIST_HEAD(&LoadPolicy.mask_list);
	get_random_bytes(&LoadPolicy.hash_salt, sizeof(LoadPolicy.hash_salt));
	LoadPolicy.cnt = 0;
	spin_lock_init(&LoadPolicy.lp_lock);
}

static inline void lp_network_entry_inc(void)
{
	LoadPolicy.cnt++;
}
static inline void lp_network_entry_dec(void)
{
	LoadPolicy.cnt--;
}
static inline unsigned int lp_hash(unsigned int net_key)
{
	return jhash_1word(net_key, LoadPolicy.hash_salt) & (LP_HASH_SIZE-1);
}
static void lp_hlist_node_free(struct load_policy_hlist_node *hnode)
{
	kfree(hnode);
}

void lp_list_node_free(struct load_policy_list_node *node)
{
	MWB_ASSERT(node->hlist_node_cnt == 0);
	kfree(node);
}
static void lp_hlist_node_free_rcu(struct rcu_head *rh)
{
	struct load_policy_hlist_node *hnode = container_of(rh, struct load_policy_hlist_node, rcu);
	lp_hlist_node_free(hnode);
	
}
static void lp_list_node_free_rcu(struct rcu_head *rh)
{
	struct load_policy_list_node *node = container_of(rh, struct load_policy_list_node, rcu);
	lp_list_node_free(node);
}
static inline void lp_list_cnt_inc(struct load_policy_list_node *node)
{
	lp_network_entry_inc();
	node->hlist_node_cnt++;
}
static void lp_list_cnt_dec(struct load_policy_list_node *node)
{
	lp_network_entry_dec();
	if(--node->hlist_node_cnt == 0){
		list_del_init(&node->list);		
		call_rcu(&node->rcu, lp_list_node_free_rcu);
	}
}

struct load_policy_list_node *lp_list_node_create(unsigned int mask )
{
	int i;
	struct load_policy_list_node *node = (struct load_policy_list_node *)kzalloc(sizeof(struct load_policy_list_node), GFP_ATOMIC);
	if(!node)
		return NULL;
	node->mask = mask;
	node->hlist_node_cnt = 0;
	INIT_LIST_HEAD(&node->list);
	init_rcu_head(&node->rcu);
	for(i = 0 ; i < sizeof(node->table)/sizeof(node->table[0]); i++)
		INIT_HLIST_HEAD(&node->table[i]);
	return node;
}
struct load_policy_hlist_node *lp_hlist_node_create(unsigned int network, unsigned int mark)
{
	struct load_policy_hlist_node *hnode = (struct load_policy_hlist_node *)kzalloc(sizeof(struct load_policy_hlist_node), GFP_ATOMIC);
	if(!hnode)
		return NULL;
	hnode->network = network;
	hnode->mark = mark;
	INIT_HLIST_NODE(&hnode->hlist);
	return hnode;
}
struct load_policy_list_node *lp_add_network_list_node(struct list_head *head, unsigned int mask)
{
	struct load_policy_list_node *node;
	node = lp_list_node_create(mask);
	if (!node){
		MWB_ERROR("lp_list_node_create FAIL");
		return NULL;
	}
	list_add_tail_rcu(&node->list, head);
	return node;
}
struct load_policy_hlist_node *lp_add_network_hlist_node(struct hlist_head *head, unsigned int network,  unsigned int mark)
{
	struct load_policy_hlist_node *hnode;
	hnode = lp_hlist_node_create(network, mark);
	if (!hnode){
		MWB_ERROR("lp_hlist_node_create FAIL");
		return NULL;
	}
	init_rcu_head(&hnode->rcu);
	hlist_add_head_rcu(&hnode->hlist, head);
	return hnode;
}
static int lp_add_network(unsigned int network, unsigned int mask, unsigned int mark)
{
	struct load_policy_list_node *node, *pos;
	struct load_policy_hlist_node *net_entry;
	unsigned int hash_id;
	struct list_head *head = &LoadPolicy.mask_list;
	network = network & mask;
	hash_id = lp_hash(network);
	#if 0
	if (list_empty(head)){
		MWB_ASSERT(LoadPolicy.cnt == 0);
		if ((node = lp_add_network_list_node(head, mask))){
			if(!lp_add_network_hlist_node(&node->table[hash_id], network, mark)){
				list_del_rcu(&node->list);
				call_rcu(&node->rcu, lp_list_node_free_rcu);
				//list_del_init(&node->list);
				//lp_list_node_free(node);
				return -1;
			}
			lp_list_cnt_inc(node);
			return 0;
		}
		return -1;
	}
	#endif
	//MWB_INFO("lp_add_network: %u.%u.%u.%u/%u.%u.%u.%u", LE_NIPQUAD(network), LE_NIPQUAD(mask))
	list_for_each_entry(pos, head, list){
		if (mask > pos->mask){			
			if ((node = lp_add_network_list_node(&pos->list, mask))){
				if(!lp_add_network_hlist_node(&node->table[hash_id], network, mark)){
					list_del_rcu(&node->list);
					call_rcu(&node->rcu, lp_list_node_free_rcu);
					return -1;
				}
				lp_list_cnt_inc(node);
				return 0;
			}
			return -1;	
		}else if(mask == pos->mask){
			hlist_for_each_entry(net_entry, &pos->table[hash_id], hlist){
				if(network == net_entry->network){
					MWB_INFO("lp_add_network: %u.%u.%u.%u/%u.%u.%u.%u exist, change mark %u to %u", 
						LE_NIPQUAD(network), LE_NIPQUAD(mask), net_entry->mark, mark);
					net_entry->mark = mark;/*exist ,update mark*/
					return 0;
				}
			}
			/* network hnode not exist, add */
			if(lp_add_network_hlist_node(&pos->table[hash_id], network, mark)){
				lp_list_cnt_inc(pos);
				return 0;
			}
			return -1;			
		}
	}
	if ((node = lp_add_network_list_node(head, mask))){
		if(!lp_add_network_hlist_node(&node->table[hash_id], network, mark)){
			list_del_rcu(&node->list);
			call_rcu(&node->rcu, lp_list_node_free_rcu);
			return -1;
		}
		lp_list_cnt_inc(node);
		return 0;
	}
	return -1;
}

static int lp_del_network(unsigned int network, unsigned int mask)
{
	struct load_policy_list_node *pos;
	struct load_policy_hlist_node *net_entry;
	struct hlist_node *n;
	unsigned int hash_id;
	list_for_each_entry(pos, &LoadPolicy.mask_list, list){
		if(pos->mask == mask){
			network = network & mask;
			hash_id = lp_hash(network);
			hlist_for_each_entry_safe(net_entry, n, &pos->table[hash_id], hlist){
				if (network == net_entry->network){
					hlist_del_init_rcu(&net_entry->hlist);//no hlist_del_init, because get_mark_from_loadpolicy need to  list-traversal
					lp_list_cnt_dec(pos);
					call_rcu(&net_entry->rcu, lp_hlist_node_free_rcu);					
					return 0;
				}
			}			
		}else if (pos->mask < mask){
			break;
		}
	}
	MWB_INFO("delete  fail,  network: %u.%u.%u.%u/%u.%u.%u.%u not exist, \n", LE_NIPQUAD(network), LE_NIPQUAD(mask));
	return -1;
}

/*make sure there are no network entry being referenced*/
static void LoadPolicy_cleanup(void)
{
	int i;
	struct load_policy_list_node *pos, *tmp;
	struct load_policy_hlist_node *net_entry;
	struct hlist_node *n;
	MWB_INFO("==========cleanup begin :LoadPolicy.cnt =%d ======", LoadPolicy.cnt);
	list_for_each_entry_safe(pos, tmp, &LoadPolicy.mask_list, list){
		for (i = 0; i < sizeof(pos->table)/sizeof(pos->table[0]); i++){
			hlist_for_each_entry_safe(net_entry, n, &pos->table[i], hlist){
				hlist_del_init(&net_entry->hlist);
				lp_hlist_node_free(net_entry);
				pos->hlist_node_cnt--;
				lp_network_entry_dec();
			}
		}
		list_del_init(&pos->list);
		lp_list_node_free(pos);
	}
	MWB_INFO("==========cleanup over :LoadPolicy.cnt =%d ,should be 0===", LoadPolicy.cnt);
	return;
}

unsigned int get_mark_from_loadpolicy(unsigned int ipaddr)
{
	unsigned int net_key;
	unsigned int hash_id;
	struct load_policy_list_node *pos;
	struct load_policy_hlist_node *net_entry;
	rcu_read_lock();
	list_for_each_entry_rcu(pos, &LoadPolicy.mask_list, list){
		net_key = ipaddr & pos->mask;
		hash_id = lp_hash(net_key);
		hlist_for_each_entry_rcu(net_entry, &pos->table[hash_id], hlist){
			if (net_key == net_entry->network){
				rcu_read_unlock();
				return net_entry->mark;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

static inline struct dst_entry *mwb_entry_dst(struct mwb_entry *me, int dir)
{
	return (struct dst_entry *)me->dst[dir];
}
static void mwb_entry_dst_set(struct mwb_entry *me, int dir, struct dst_entry *dst)
{
	MWB_ASSERT(me);
	MWB_ASSERT(dst);
	spin_lock(&me->dst_lock[dir]);
	mwb_entry_dst_drop(me, dir);
	me->dst[dir] = (unsigned long)dst;
	dst_hold(dst);
	spin_unlock(&me->dst_lock[dir]);
}
static inline bool mwb_rt_is_expired(struct rtable *rth)
{
	return rth->rt_genid != atomic_read(&dev_net(rth->dst.dev)->ipv4.rt_genid);
}
static bool mwb_rt_cache_valid(struct mwb_entry *me, int dir)
{
	struct rtable *rt = (struct rtable *)me->dst[dir];
	return	rt &&
		rt->dst.obsolete == DST_OBSOLETE_FORCE_CHK &&
		!mwb_rt_is_expired(rt);
}
static unsigned int mwb_input_route(struct sk_buff *skb, struct mwb_entry *me, int dir)
{
	struct rtable *rt;
	struct iphdr *iph = ip_hdr(skb);
	int err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, skb->dev);
	if (unlikely(err)) {
		return err;
	}
	rt = skb_rtable(skb);
	if(likely(rt->rt_type == RTN_UNICAST || rt->rt_type == RTN_LOCAL)){
		mwb_entry_dst_set(me, dir, &rt->dst);
	}
	return 0;
}
static inline void  mwb_entry_save_line(struct mwb_entry *me)
{
	me->line_mask = mwb_lines.line_mask;
}
static inline uint8_t mwb_new_line(struct mwb_entry *me)
{
	return mwb_lines.line_mask & (~(me->line_mask));
}
#if 0
static inline uint8_t mwb_is_chose_newline(struct mwb_entry *me, int mark)
{
	MWB_ASSERT(mark);
	return mwb_new_line(me) & (1u << (mark-1));
}
#endif
static inline uint8_t mwb_is_chose_newline(uint8_t new_line, int mark)
{
	MWB_ASSERT(mark);
	return new_line & (1u << (mark-1));
}
/*if bind dst to mwb_entry, it means pair of sip and dip bind the same dst, so ignore the route with tos*/
static unsigned int mwb_hook_fn(/*unsigned int hook*/const struct nf_hook_ops *ops,
					struct sk_buff *skb,
				     const struct net_device *in,
				     const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct iphdr *iph;
	struct mwb_entry *me;
	struct mwb_key_info mki;
	unsigned int mark;
	struct rtable *rt;
	int err;
	int dir;
	uint8_t new_line;
	
	if (!in) {
		return NF_ACCEPT;
	}

	//if(mwb_lines.line_alive_cnt < 2)
	//	return NF_ACCEPT;
	if(mwb_lines.line_mask == 0)
		return NF_ACCEPT;
	
	iph = ip_hdr(skb);
	if ((iph->protocol != IPPROTO_TCP) 
		&& (iph->protocol != IPPROTO_UDP) 
		&& (iph->protocol != IPPROTO_ICMP)) 
	{
		return NF_ACCEPT;
	}

	if (ipv4_is_lbcast(iph->saddr) || 
		ipv4_is_lbcast(iph->daddr) ||
			ipv4_is_loopback(iph->saddr) || 
			ipv4_is_loopback(iph->daddr) ||
			ipv4_is_multicast(iph->saddr) ||
			ipv4_is_multicast(iph->daddr) || 
			ipv4_is_zeronet(iph->saddr) ||
			ipv4_is_zeronet(iph->daddr) || 
			ipv4_is_lgroup(iph->saddr) || 
			ipv4_is_lgroup(iph->daddr))
	{
		return NF_ACCEPT;
	}
	
	if (skb->_skb_refdst) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL) {
		MWB_DEBUG("ct is NULL, protocol: %d\n", (int)iph->protocol);
		return NF_ACCEPT;
	}
	if (nf_ct_is_untracked(ct)) {
		MWB_DEBUG("untracked ct, protocol: %d\n", (int)iph->protocol);
		return NF_ACCEPT;
	}
	
	dir = CTINFO2DIR(ctinfo);
	rcu_read_lock();
	if((me = (struct mwb_entry *)ct->mwb_entry))
		goto set_dst;
	
	if(skb->mark){
		goto out;
	}else if (ct->mark){
		skb->mark = ct->mark;
		goto out;
	}	

	if (skb->nfctinfo != IP_CT_NEW)
		goto out;
	
	if(strncmp(in->name, "br", 2))
		goto out;

	/* if ct->mark == 0,skb is new and unmark . go for user load policy*/
	if (LoadPolicy.cnt){
		skb->mark = get_mark_from_loadpolicy(ntohl(iph->saddr));
		if(skb->mark){
			if(!check_line_alive_by_mark(skb->mark & (~LOADPOLICY_MARK))){
				MWB_INFO("==%u.%u.%u.%u->%u.%u.%u.%u mark =%u line down,so go to multiwan balance\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), skb->mark);
				skb->mark = 0;
			}else{
				ct->mark = skb->mark;
				goto out;
			}
		}
	}
	
	if(mwb_lines.type){
		skb->mark = mwb_chose_routine_by_traffic();
		ct->mark = skb->mark;
		goto out;
	}
	
	mwb_key_info_get(skb, &mki);
	me = mwb_entry_find(&mki);
	if (me){
		//me_ct_attach(ct, me);
		me->timestamp = jiffies;
		if(!check_line_alive_by_mark(me->mark)){
			if(likely(mark = mwb_chose_routine_by_traffic())){			
				skb->mark = mark;				
				if(mwb_input_route(skb, me, dir)){
					rcu_read_unlock();
					return NF_DROP;
				}
				me->mark = mark;
				ct->mark = mark;
				//here ,may be tme dst change, so he old ct int the me will change to new routine, so may be ct will disconnect
				me_ct_attach(ct, me);
				mwb_entry_save_line(me);
				MWB_INFO("==%u.%u.%u.%u->%u.%u.%u.%u change routine :me->mark =%u ", 
					NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), me->mark);
				if(mwb_entry_dst(me, dir))
					MWB_INFO("change routine : me->dst->__refcnt =%d ,dst->dev=%s ", atomic_read(&(mwb_entry_dst(me, dir))->__refcnt), (mwb_entry_dst(me, dir))->dev->name);									
			}
			goto out;
		}
		if ((new_line = mwb_new_line(me))){	
			mwb_entry_save_line(me);
			if(time_before(jiffies, g_line_change_jiffies+CHECK_ENTRY_INTVL+MWB_ENTRY_TIMEOUT_MAX)){
				mark = mwb_chose_routine_by_traffic();
				if (mark && mwb_is_chose_newline(new_line, mark)){												
					skb->mark = mark;	
					/*
						here,just because get new line, the old ct is ok, so just detach and change me dst
						if detach after change me dst, this moment skb of the old ct will use new me dst, the old ct maybe lost this skb
					*/					
					spin_lock_bh(&me->ct_list_lock);
					mwb_entry_detach_all_ct(me);
					spin_unlock_bh(&me->ct_list_lock);						
					if(mwb_input_route(skb, me, dir)){
						rcu_read_unlock();
						return NF_DROP;
					}
					me->mark = mark;
					ct->mark = me->mark;
					me_ct_attach(ct, me);					
					goto out;
				}
			}			
		}
		ct->mark = me->mark;
		me_ct_attach(ct, me);
				
	set_dst:
		//MWB_ASSERT(ct->mark);
		//me->timestamp = jiffies;//should update timestamp	
		skb->mark = ct->mark;
		if(mwb_rt_cache_valid(me, dir)){
			skb_dst_set_noref(skb, mwb_entry_dst(me, dir));
		}else{
			// the line is invalid, goto match main table , if the skb is linked data,no problem, 
			//if not, match main table default route, maye be disconnect happen
			if(mwb_input_route(skb, me, dir)){
				rcu_read_unlock();
				return NF_DROP;
			}
		}
	}else{	
		skb->mark = mwb_chose_routine_by_traffic();
		ct->mark = skb->mark;		
		if(unlikely(!skb->mark)){
			goto out;
		}
		
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, skb->dev);
		if (unlikely(err)) {
			rcu_read_unlock();
			return NF_DROP;
		}

		rt = skb_rtable(skb);		
		if(rt->rt_type != RTN_UNICAST && rt->rt_type != RTN_LOCAL){
			MWB_INFO("not unicastr: %u.%u.%u.%u->%u.%u.%u.%u rt->rt_type=%u  ", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), rt->rt_type);
			goto out;
		}
		if(likely(me = mwb_entry_add(&mki, skb))){
			me_ct_attach(ct, me);
			mwb_entry_save_line(me);
		}else{
			MWB_WARN("mwb_entry_add user: %u.%u.%u.%u->%u.%u.%u.%u ct->mark=%u  fail", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ct->mark);
			goto out;
		}
		mwb_entry_dst_set(me, dir, &rt->dst);
		MWB_INFO("====mwb_entry hold dst: %u.%u.%u.%u->%u.%u.%u.%u dst->dev=%s, dst->__refcnt=%d,dst=%lx,mark=%u==== ", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), 
									(mwb_entry_dst(me, dir))->dev->name, atomic_read(&(mwb_entry_dst(me, dir))->__refcnt), me->dst[dir], me->mark);
	}
out:		
	rcu_read_unlock();	
	return NF_ACCEPT;
}
static unsigned int mwb_hook_dev_stats_fn(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
				     const struct net_device *in,
				     const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
{
	int i;
	uint8_t mask;
	struct mwb_cpu_dev_stats *stats;
	struct line_info_st *li;
	if (!in ||!out)
		return NF_ACCEPT;
	rcu_read_lock();
	mask = mwb_lines.line_mask;
	MWB_LINE_MASK_FOR_EACH(i, mask){	
		li = &mwb_lines.line_info[i];
		if (likely(li->dev)){
			stats = (struct mwb_cpu_dev_stats *)this_cpu_ptr(li->stats);
			if (!stats)
				continue;
			if (li->dev == out){
				u64_stats_update_begin(&stats->syncp);
				stats->tx_bytes += skb->len;
				u64_stats_update_end(&stats->syncp);
				break;
			}
			if (li->dev == in){
				u64_stats_update_begin(&stats->syncp);
				stats->rx_bytes += skb->len;
				u64_stats_update_end(&stats->syncp);
				break;
			}
		}	
	}
	rcu_read_unlock();
	return NF_ACCEPT;
}
static struct nf_hook_ops mwb_hooks[] __read_mostly = {
	{
		.hook = mwb_hook_fn,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST + 1,
	},
	{
		.hook = mwb_hook_dev_stats_fn,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 1,
	},
};
void  mwb_ht_cleanup(struct HashTable *ht)
{
	del_timer_sync(&ht->ktimer);
	hash_table_cleanup(ht);
	rcu_assign_pointer(mwb_ct_detach, NULL);
	do{
		//synchronize_rcu_bh();
		synchronize_rcu();
		MWB_INFO("wait to cleaup all entry, counter=%d", atomic_read(&ht->counter));
	}while(atomic_read(&ht->counter) != 0);
	ht_tbpool_destroy(ht);
	if(ht->hcache) {
	    kmem_cache_destroy(ht->hcache);
	}
}
void mwb_lines_cleanup(void)
{
	int i;
	del_timer_sync(&mwb_lines.timer);
	MWB_LINE_MASK_FOR_EACH(i, mwb_lines.line_mask){
		if(mwb_lines.line_info[i].stats) {
			free_percpu(mwb_lines.line_info[i].stats);
		}
	}
	memset(&mwb_lines, 0, sizeof(mwb_lines));	
}
void me_ct_attach(struct nf_conn *ct, struct mwb_entry *me)
{	
	spin_lock(&me->ct_list_lock);
	if (me->deleted){
		spin_unlock(&me->ct_list_lock);
		return;
	}
	list_add_tail(&ct->list, &me->ct_list);
	spin_unlock(&me->ct_list_lock);
	ct->mwb_entry = me;
	atomic_inc(&me->refcnt);
}

void me_ct_detach(struct nf_conn *ct)
{
	struct mwb_entry *me = (struct mwb_entry *)(ct->mwb_entry);
	if(me){				
		spin_lock(&me->ct_list_lock);
		if (!list_empty(&ct->list)){
			list_del_init(&ct->list);
			atomic_dec(&me->refcnt);
			ct->mwb_entry = NULL;
		}
		spin_unlock(&me->ct_list_lock);
	}	
}

static void mwb_fib_magic(int cmd, int type, __be32 dst, int dst_len, struct in_ifaddr *ifa)
{
	int i;
	struct net *net = dev_net(ifa->ifa_dev->dev);
	struct fib_table *tb;
	struct fib_config cfg = {
		.fc_protocol = RTPROT_KERNEL,
		.fc_type = type,
		.fc_dst = dst,
		.fc_dst_len = dst_len,
		.fc_prefsrc = ifa->ifa_local,
		.fc_oif = ifa->ifa_dev->dev->ifindex,
		.fc_nlflags = NLM_F_CREATE | NLM_F_APPEND,
		.fc_nlinfo = {
			.nl_net = net,
		},
	};

	MWB_ASSERT(type == RTN_UNICAST);
	for(i = 1 ; i < MLINES_MAX + 1; i ++){	
		//tb = fib_new_table(net, RT_TABLE_MAIN);
		tb = fib_new_table(net, i);
		if (tb == NULL){
			MWB_WARN(" table_id %d not exit ,should check /etc/iproute/rt_table", i);
			continue;
		}
		printk(" i=%d, dev name=%s,===\n",i,ifa->ifa_dev->dev->name);
		cfg.fc_table = tb->tb_id;
		cfg.fc_scope = RT_SCOPE_LINK;

		if (cmd == RTM_NEWROUTE)
			fib_table_insert(tb, &cfg);
		else
			fib_table_delete(tb, &cfg);
	}
}
void mwb_fib_add_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *prim = ifa;
	__be32 mask = ifa->ifa_mask;
	__be32 addr = ifa->ifa_local;
	__be32 prefix = ifa->ifa_address & mask;
	
	if (ifa->ifa_flags & IFA_F_SECONDARY) {
		prim = inet_ifa_byprefix(in_dev, prefix, mask);
		if (prim == NULL) {
			pr_warn("%s: bug: prim == NULL\n", __func__);
			return;
		}
	}

	//fib_magic(RTM_NEWROUTE, RTN_LOCAL, addr, 32, prim);

	if (!(dev->flags & IFF_UP))
		return;	

	if (!ipv4_is_zeronet(prefix) && !(ifa->ifa_flags & IFA_F_SECONDARY) &&
	    (prefix != addr || ifa->ifa_prefixlen < 32)) {
	    	if(!(dev->flags & IFF_LOOPBACK))
			mwb_fib_magic(RTM_NEWROUTE, RTN_UNICAST,
			  	prefix, ifa->ifa_prefixlen, prim);
	}
}

void mwb_fib_del_ifaddr(struct in_ifaddr *ifa, struct in_ifaddr *iprim)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	//struct in_ifaddr *ifa1;
	struct in_ifaddr *prim = ifa;
	//__be32 brd = ifa->ifa_address | ~ifa->ifa_mask;
	__be32 any = ifa->ifa_address & ifa->ifa_mask;

	if (ifa->ifa_flags & IFA_F_SECONDARY) {
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (prim == NULL) {
			pr_warn("%s: bug: prim == NULL\n", __func__);
			return;
		}
		if (iprim && iprim != prim) {
			pr_warn("%s: bug: iprim != prim\n", __func__);
			return;
		}
	} else if (!ipv4_is_zeronet(any) &&
		   (any != ifa->ifa_local || ifa->ifa_prefixlen < 32)) {
		    if(!(dev->flags & IFF_LOOPBACK))
				mwb_fib_magic(RTM_DELROUTE,
						 RTN_UNICAST,
			  				any, ifa->ifa_prefixlen, prim);
	}
}
static int mwb_fib_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	printk("========dump_stack begin=============\n");
	//dump_stack();
	printk("========dump_stack over=============\n");
	switch (event) {
	case NETDEV_UP:
		mwb_fib_add_ifaddr(ifa);
		break;
	case NETDEV_DOWN:
		mwb_fib_del_ifaddr(ifa, NULL);
		break;
	}
	return NOTIFY_DONE;
}

static int mwb_fib_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;
	int i;
	uint8_t mask;
	struct mwb_cpu_dev_stats __percpu *stats_free = NULL;
	struct line_info_st *li;
	if (event == NETDEV_UNREGISTER) {
		return NOTIFY_DONE;
	}

	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		for_ifa(in_dev) {
			mwb_fib_add_ifaddr(ifa);
		} endfor_ifa(in_dev);
		break;
	case NETDEV_DOWN:	
		mask = mwb_lines.line_mask;			
		MWB_LINE_MASK_FOR_EACH(i, mask){	
			li = &mwb_lines.line_info[i];
			if (li->dev == dev){	
				spin_lock_bh(&mwb_lines.line_lock);
				if (MWB_LINE_MASK_CHECK(mwb_lines.line_mask, i)){
					mwb_lines.line_alive_cnt--;
					MWB_LINE_MASK_CLR(mwb_lines.line_mask, i);	
					stats_free = li->stats;
					//li->stats = NULL;
					memset(li, 0, sizeof(struct line_info_st));
				}
				spin_unlock_bh(&mwb_lines.line_lock);	
				MWB_INFO("=============dev =%s, line_on =%d, DOWN=============", dev->name, i);
				break;
			}	
		}		
		if (stats_free){
			mwb_iprule_del(line_no);
			synchronize_net();
			free_percpu(stats_free);
		}
		
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGE:
		break;
	}
	return NOTIFY_DONE;
}
struct notifier_block mwb_fib_netdev_notifier = {
	.notifier_call =  mwb_fib_netdev_event,
};
struct notifier_block mwb_fib_inetaddr_notifier = {
	.notifier_call =  mwb_fib_inetaddr_event,
};

static void mwb_rules_ops_put(struct fib_rules_ops *ops)
{
	if (ops)
		module_put(ops->owner);
}
static struct fib_rules_ops *mwb_lookup_rules_ops(struct net *net, int family)
{
	struct fib_rules_ops *ops = NULL;
	rcu_read_lock();
	list_for_each_entry_rcu(ops, &net->rules_ops, list) {
		if (ops->family == family) {
			if (!try_module_get(ops->owner))
				ops = NULL;
			rcu_read_unlock();
			return ops;
		}
	}
	rcu_read_unlock();
	return NULL;
}
static int mwb_iprule_set( int line_no)
{
	struct fib_rules_ops *ops = NULL;
	struct fib_rule *r, *rule = NULL, *last =  NULL;
	struct net *net = &init_net;
	int err = -1;
	#if 0
	if (!try_module_get(net->ipv4.rules_ops->owner)){
		return err;
	}
	ops = net->ipv4.rules_ops;
	#else
	ops = mwb_lookup_rules_ops(net, AF_INET);
	#endif
	if (!ops){
		return err;
	}
	rule = kzalloc(ops->rule_size, GFP_KERNEL);
	if (rule == NULL) {
		err = -ENOMEM;
		goto errout;
	}
	rule->pref = line_no + 1001;
	rule->mark = line_no + 1;
	rule->mark_mask = 0xff;
	rule->table = line_no + 1;
	rule->action = FR_ACT_TO_TBL;
	rule->flags = 0;
	rule->fr_net = hold_net(ops->fro_net);
	
	rule->suppress_prefixlen = -1;
	rule->suppress_ifgroup = -1;

	//there is maybe the same pref
	list_for_each_entry(r, &ops->rules_list, list) {
		if (r->pref > rule->pref)
			break;
		last = r;
	}
	
	atomic_set(&rule->refcnt, 1);//fib_rule_get(rule);

	if (last)
		list_add_rcu(&rule->list, &last->list);
	else
		list_add_rcu(&rule->list, &ops->rules_list);

	/* need to flush route cache when add a iprule ?, system will flush_cache :atomic_inc(&net->ipv4.rt_genid);*/
	//flush_route_cache(ops);
	//if (ops->flush_cache)
	//	ops->flush_cache(ops);//fib4_rule_flush_cache
errout:
	mwb_rules_ops_put(ops);
	return err;
}
static int mwb_iprule_del(int line_no)
{
	struct fib_rules_ops *ops = NULL;
	struct fib_rule *rule = NULL;
	struct net *net = &init_net;
	int err = -1;
	unsigned int del_pref = 1001 + line_no;
	
	ops = mwb_lookup_rules_ops(net, AF_INET);
	if (!ops){
		return err;
	}
	list_for_each_entry(rule, &ops->rules_list, list) {
		/*make sure trave all rules when there are multi rules get the same pref*/
		if(rule->pref > del_pref)
			break;
		if(!(rule->pref == del_pref && rule->table == 1 + line_no
				&& rule->action == FR_ACT_TO_TBL && rule->mark_mask == 0xff))
			continue;

		list_del_rcu(&rule->list);
		
		if (ops->delete)
			ops->delete(rule);//fib4_rule_delete
		//release_net(ops->fro_net);//fib_rule_put -> fib_rule_put_rcu  will do release_net()
		fib_rule_put(rule);
		//flush_route_cache(ops);
		//if (ops->flush_cache)
		//	ops->flush_cache(ops);//fib4_rule_flush_cache
		mwb_rules_ops_put(ops);
		return 0;
	}
	mwb_rules_ops_put(ops);
	return err;
}
int mwb_module_init(void){
	int ret = 0;
	if(!(mwbHashTable = mwb_ht_init()))
		goto __err;
	mwb_lines_init();
	ret = nf_register_hooks(mwb_hooks, ARRAY_SIZE(mwb_hooks));
	if (ret < 0) {
		MWB_ERROR("register hook failed.\n");
		goto cleanup_ht;
	}
	printk("MWB register hook success!\n");	
	ret = mline_sysfs_register();
	if (ret < 0) {
		printk("sysfs_create_file failed.\n");
		goto unreg_hook;
	}
	rcu_assign_pointer(mwb_ct_detach, me_ct_detach);
	LoadPolicy_init();
	register_netdevice_notifier(&mwb_fib_netdev_notifier);
	register_inetaddr_notifier(&mwb_fib_inetaddr_notifier);	
	printk("multiple wan balance init!\n");	
	return 0;

unreg_hook:
	nf_unregister_hooks(mwb_hooks, ARRAY_SIZE(mwb_hooks));	
cleanup_ht:
	mwb_ht_cleanup(mwbHashTable);
__err:
	printk("error : multiple wan balance fail!\n");
	return ret;	
}
void mwb_module_fini(void){	
	mline_sysfs_unregister();
	nf_unregister_hooks(mwb_hooks, ARRAY_SIZE(mwb_hooks));	
	//rcu_assign_pointer(mwb_ct_detach, NULL); //do it after mwb_ht_cleanup()-> hash_table_cleanup(), avoid ct has free before me detach ct
	synchronize_net();
	mwb_ht_cleanup(mwbHashTable);
	mwb_lines_cleanup();
	printk("mwb_lines_cleanup over!\n");
	LoadPolicy_cleanup();
	printk("LoadPolicy_cleanup over!\n");
	unregister_netdevice_notifier(&mwb_fib_netdev_notifier);
	unregister_inetaddr_notifier(&mwb_fib_inetaddr_notifier);
	printk("multiple wan balance exit over!\n");

	rcu_barrier();
	/* Wait for completion of call_rcu()'s , 
		timer's mwb_entry call_rcu, there is cnt(mwbHashTable->cnt) to make sure call_rcu finish 
	*/
}
module_init(mwb_module_init);
module_exit(mwb_module_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MO JIAN WEI");
MODULE_DESCRIPTION("multiple wan balance");
MODULE_VERSION("0.1");
