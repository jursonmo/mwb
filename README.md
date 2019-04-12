### mwb  (multi wan balance): 多wan负载均衡

##### 相对原来做法的改进：

+ 少用了很多iptables conntrack connmark, --save-mark or --restore-mark
+ 自动添加本地路由到策略路由表，跟main路由表一样，应用层不需要配置wan ip是还要往策略路由表里加
+ 区分匹配用户自定义策略连接，　ip ru add mark/0xf table table1，cat nf_conntrack 通过mark值不同来区分
+ 连接绑定路由缓存，即每个连接只查找一次路由，之后该连接的所有数据包直接拿到路由信息并转发，提高转发效率，(同时把ip early demux 置0,也可相对提高转发效率， ip early demux作用是先查找skb属于哪个sk, 把sk的dst赋予给skb,这样就不用再查找路由了，对于来到本地的数据,这样提高了效率.如果是转发数据比较多，这样反而降低了效率) 
+ 根据每个wan口流量的占用比例来负载
+ 根据wan状态变化，策略路由自动添加及删除，main表默认路由的添加及删除
+ 均衡的单位（颗粒度）可以是连接connection, 也可以是“源地址和目的地址”的组合（这样保证某个pc跟某个服务器的数据一直就走同一个wan口）



##### 以后可以优化地方或缺点

+  dns负载均衡,　在dns解释时就考虑负载的情况，不同isp线路情况回应dns 结果. 
+ 没有考虑wan 口在不同isp 的情况. 当wan0 带宽剩余比较多，拦截客户端的dns解析，重定向到wan0 线路的isp dns 服务器上解析，这样解析出来的结果大多是该isp 下的服务器ip. 再根据解析的结果添加到路由表里，走wan0. 或者根据各个运营商的路由表路由
