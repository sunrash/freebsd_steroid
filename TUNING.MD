/boot/loader.conf
net.isr.maxthreads="-1"
net.inet.tcp.syncache.hashsize="1024" # (default 512)
net.inet.tcp.syncache.bucketlimit="100" # (default 30)
hw.intr_storm_threshold="17888" # (default 1000)
tcp_rack_load=YES
intel-isa-aes_load=YES
mlx5_load=YES
mlx5en_load=YES


/etc/sysctl.conf
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
vfs.read_max=128

vfs.zfs.delay_min_dirty_percent=96  # (default 60%)
vfs.zfs.dirty_data_max=12884901888  # (default, 10% of RAM or up to 4GB)
vfs.zfs.dirty_data_sync=12348030976 # (default 67108864, 64MB)
vfs.zfs.min_auto_ashift=12          # (default 9, 512 byte, ashift=9)
vfs.zfs.top_maxinflight=128         # (default 32)
vfs.zfs.trim.txg_delay=2            # (default 32, 32*5secs=160 secs)
vfs.zfs.txg.timeout=90              # (default 5 sec)
vfs.zfs.vdev.aggregation_limit=1048576 # (default 131072, 128KB)
vfs.zfs.vdev.write_gap_limit=0      # (default 4096, 4KB)

