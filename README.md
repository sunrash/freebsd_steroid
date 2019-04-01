Freebsd for Video Streaming on 100Gb/s - 200Gb/s on single core

Stack: Freebsd (HEAD) + TCP MBUF PATCH + TCP_RACK + INTEL-ISA + NGINX (SSL_SENDFILE) + HW & SW Offload + Tuning for Best perfomance 

# BUILD & TUNING INSTRUCTIONS

For AMD64 only  


## Test env 

Mellanox based env:
```
1x CPU: Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz (2600.05-MHz K8-class CPU)
6x 64GB @ DDR4 2400 Samsung 
1x Mellanox Technologies Mellanox MCX555A-ECAT 100IB + 100GBE @ 1xQSPF28
1x Samsung 970 2TB NVME SSD for nginx cache
1x SSD 240GB (6G) for system
NUMA off 
HT off
A7 mode DRAM off
POR DRAM off
```

Chelsio based env:
```
1x CPU: Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz (2600.05-MHz K8-class CPU)
6x 64GB @ DDR4 2400 Samsung
1x Chelsio T6 T62100-CR  + 100GBE @ 1xQSPF28
1x Samsung 970 2TB NVME SSD for nginx cache
1x SSD 240GB (6G) for system
NUMA off
HT off
A7 mode DRAM off
POR DRAM off
```


For Mellanox NIC card:
## /boot/loader.conf
```
net.isr.maxthreads="-1"
net.isr.bindthreads="1"
net.inet.tcp.hostcache.cachelimit="0"
net.inet.tcp.syncache.hashsize="2048" # (default 512)
net.inet.tcp.syncache.bucketlimit="300" # (default 30)
hw.intr_storm_threshold="37888" # (default 1000)
net.isr.defaultqlimit=4096 # (default 256)
net.link.ifqmaxlen=2048  # (default 50)
tcp_rack_load=YES
intel-isa-aes_load=YES
mlx5_load=YES
mlx5en_load=YES
hint.p4tcc.0.disabled=1
hint.acpi_throttle.0.disabled=1
```
For Chelsio card:
## /boot/loader.conf
```
net.inet.tcp.hostcache.cachelimit="0"
net.inet.tcp.syncache.hashsize="2048" # (default 512)
net.inet.tcp.syncache.bucketlimit="300" # (default 30)
hw.intr_storm_threshold="37888" # (default 1000)
net.isr.defaultqlimit=4096 # (default 256)
net.link.ifqmaxlen=2048  # (default 50)
tcp_rack_load=YES
intel-isa-aes_load=YES
hint.p4tcc.0.disabled=1
hint.acpi_throttle.0.disabled=1
t5fw_cfg_load="YES"
if_cxgbe_load="YES"
```

Both for Mellanox + Chelsio NIC card
## /etc/sysctl.conf
```
kern.ipc.maxsockbuf=614400000  # (wscale 14)
net.inet.tcp.recvbuf_inc=65536     # (default 16384)
net.inet.tcp.sendbuf_inc=65536     # (default 8192)
net.inet.tcp.sendspace=65536       # (default 32768)
net.inet.tcp.mssdflt=1460   # (default 536)
net.inet.tcp.minmss=536  # (default 216)
net.inet.tcp.rfc6675_pipe=1  # (default 0)
net.inet.tcp.syncache.rexmtlimit=0  # (default 3)
net.inet.ip.maxfragpackets=0     # (default 63474)
net.inet.ip.maxfragsperpacket=0  # (default 16)
net.inet6.ip6.maxfragpackets=0   # (default 507715)
net.inet6.ip6.maxfrags=0         # (default 507715)
net.inet.tcp.abc_l_var=44   # (default 2) if net.inet.tcp.mssdflt=1460
net.inet.tcp.initcwnd_segments=44            # (default 10) if net.inet.tcp.mssdflt = 1460
net.inet.tcp.syncookies=0  # (default 1)
net.inet.tcp.isn_reseed_interval=4500  # (default 0, disabled)
kern.random.fortuna.minpoolsize=128  # (default 64)
net.inet.icmp.drop_redirect=1     # (default 0)
net.inet.ip.check_interface=1     # (default 0)
net.inet.ip.portrange.first=1024  # (default 10000)
net.inet.ip.portrange.randomcps=9999 # (default 10)
net.inet.ip.portrange.randomtime=1 #(default 45 secs)
net.inet.ip.random_id=1           # (default 0)
net.inet.ip.redirect=0            # (default 1)
net.inet.sctp.blackhole=2         # (default 0)
net.inet.tcp.blackhole=2          # (default 0)
net.inet.tcp.drop_synfin=1        # (default 0)
net.inet.tcp.ecn.enable=1         # (default 2)
net.inet.tcp.fast_finwait2_recycle=1 # (default 0)
net.inet.tcp.fastopen.client_enable=0 # (default 1)
net.inet.tcp.fastopen.server_enable=0 # (default 0)
net.inet.tcp.finwait2_timeout=1000 # (default 60000)
net.inet.tcp.icmp_may_rst=0       # (default 1)
net.inet.tcp.keepcnt=2            # (default 8)
net.inet.tcp.keepidle=62000       # (default 7200000)
net.inet.tcp.keepinit=5000        # (default 75000)
net.inet.tcp.msl=2500             # (default 30000)
net.inet.tcp.path_mtu_discovery=0 # (default 1)
net.inet.udp.blackhole=1          # (default 0)
net.inet.tcp.functions_default=rack  # (default freebsd)
net.inet.tcp.rack.tlpmethod=3  # (default 2, 0=no-de-ack-comp, 1=ID, 2=2.1, 3=2.2)
net.inet.tcp.rack.data_after_close=0  # (default 1)
kern.coredump=0            # (default 1)
kern.sugid_coredump=0        # (default 0)
kern.ipc.tls.disable=0 # (default 0)
kern.ipc.tls.ifnet.permitted=0 (default 0)
vfs.read_max=128
kern.ipc.somaxconn=8096 (default 128)
net.inet.icmp.icmplim=1 (default 200)
net.inet.icmp.icmplim_output=0  # (default 1)
net.inet.tcp.hostcache.expire=3900  # (default 3600)
net.inet.tcp.delacktime=20 # (default 100)
kern.threads.max_threads_per_proc=9000 (default 1500)
kern.sched.interact=5 # (default 30)
kern.sched.slice=3    # (default 12)
net.inet.tcp.keepidle=10000 (default 65000)
net.inet.tcp.keepintvl=5000 (default 75000)
net.inet.ip.intr_queue_maxlen=2048  # (default 256)
net.route.netisr_maxqlen=2048       # (default 256)
net.inet.raw.maxdgram=16384       # (default 9216)
net.inet.raw.recvspace=16384      # (default 9216)
kern.random.harvest.mask=351  # (default 511)
kern.ipc.shm_use_phys=1 # (default 0)
```


### COMPILE INSTRUCTIONS
```
mkdir /root/JP/
git clone SRC to /root/JP/
cd /root/JP/freebsd_steroids/

make -j16 buildkernel KERNCONF=STEROIDS && make -j16 buildworld TARGET=amd64
make -j16 installkernel KERNCONF=STEROIDS && make -j16 installworld

reboot 
```
apply parametrs /etc/sysctl.conf & /boot/loader.conf 
```
cd /root/JP/freebsd_steroids/netflix/kmod/intel-isa-aes 
make clean install
cd /root/JP/freebsd_steroids/netflix/nginx_x.xx.x
```
for mellanox (HW+SW):
```
./configure --with-http_ssl_module --with-http_v2_module --with-http_auth_request_module --with-http_mp4_module --with-http_stub_status_module --with-openssl=/root/JP/feebsd_steroids/netflix/openssl-kern_tls_1_0_2 --with-cc-opt="-I /root/JP/feebsd_steroids/netflix/openssl-kern_tls_1_0_2/.openssl/include" --with-ld-opt="-L /root/JP/feebsd_steroids/netflix/openssl-kern_tls_1_0_2/.openssl/lib" --prefix=/rtbngx
make clean install
```
/rtbngx for start nginx
 
for Chelsio (HW):
```
./configure --with-http_ssl_module --with-http_v2_module --with-http_auth_request_module --with-http_mp4_module --with-http_stub_status_module --with-openssl=/root/JP/feebsd_steroids/netflix/openssl-chelsio_toe_1_1_1 --with-cc-opt="-I /root/JP/feebsd_steroids/netflix/openssl-chelsio_toe_1_1_1/.openssl/include" --with-ld-opt="-L /root/JP/feebsd_steroids/netflix/openssl-chelsio_toe_1_1_1/.openssl/lib" --prefix=/rtbngx
make clean install
```
/rtbngx for start nginx


## Nginx.conf
```

worker_processes  15;
worker_cpu_affinity auto;

events {
    worker_connections  650535;
    use kqueue;
}


http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout  65;
    reset_timedout_connection on;
    keepalive_requests 100;
    send_timeout 2;
    server {
        listen       443 ssl http2;
        server_name  z.rutube.ru;
        ssl_protocols        TLSv1.1 TLSv1.2;
        ssl_certificate      cert.crt;
        ssl_certificate_key  cert.key;

        ssl_session_cache shared:SSL:8024m; # holds approx XXXXXXX sessions
        ssl_session_timeout 6h; # 6 hour during which sessions can be re-used.
        ssl_buffer_size 16k; # maybe large buffer better than smal   
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256; # best & cheap perfomance 
        ssl_prefer_server_ciphers  on;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
```

Specials thanx for FreeBSB team, Netflix OCA Team, Mellanox & Chelsio team. 
