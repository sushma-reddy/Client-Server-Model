1. Make a network topology, as given in the report 

2. In authenticator 
   sudo apt-get update
   sudo apt-get install make 
   sudo apt-get install build-essential 
   sudo apt-get install apache2
   make a directory and copy firewall.c, Makefile
   make (to compile the kernel module)
   sudo insmod firewall.ko

3. In web-server
   sudo apt-get update
   sudo apt-get install apache2
   copy index.php to /var/www/html/

4. In controller
   sudo apt-get update
   sudo apt-get install git
   git clone http://github.com/noxrepo/pox
   cd pox
   copy app.py to pox/forwarding/
   ./pox.py forwarding.app > log
   
5. In OVS
   sudo apt-get update
   sudo apt-get install openvswitch-switch
   sudo apt-get install openvswitch-common
   sudo apt-get install openvswitch-controller
   ovs-vsctl add-br br0
   ovs-vsctl add-port eth0
   ovs-vsctl add-port eth1
   ovs-vsctl add-port eth2
   ovs-vsctl add-port eth3
   sudo ifconfig eth0 up 0
   sudo ifconfig eth1 up 0
   sudo ifconfig eth2 up 0
   sudo ifconfig eth3 up 0
   sudo ifconfig br0 ip_address up
   ovs-vsctl set-controller br0 tcp:controller_IP:6633
   ovs-vsctl set-fail-mode br0 secure
   0vs-ofctl del-flows br0



6. In Client
   Linux:curl http://server-ip 
   Windows:use browser http://server-ip

Note:ping from auth to web-server such that the controller discover the topology.
     Valid client will get response where as no response for invalid client.