#testing : mwb by mo , on github, I can see it anywhere
相对好处：
　　a.少用了很多iptables  conntrack  connmark,   --save-mark or --restor-mark
    b.路由表自动添加本地路由
　　c.区分自定义策略连接，　ip ru add   mark/0xf  table  table1，然后cat nf_conntrack
    d.绑定路由缓存，每个连接只查找一次路由。提高转发效率，(同时把ip early demux 置0,也可相对提高转发效率)
还可以优化地方：
a.  上下行流量判断
b.  根据wan状态变化，策略路由自动添加及删除，main表默认路由的添加及删除
c.  dns负载均衡,　在dns解释时就考虑负载的情况，不同isp线路情况回应dns 结果。
