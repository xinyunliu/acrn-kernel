ssh root@dp7-kbl.sh.intel.com mount /dev/sda1 /mnt/sda1
scp /home/woliu/Work/eb_native/out/sos_kernel/arch/x86/boot/bzImage root@dp7-kbl.sh.intel.com:/mnt/sda1/EFI/org.xyl/sos_waag.img
rsync -avzz /home/woliu/Work/eb_native/out/sos_rootfs/lib/modules/* root@dp7-kbl.sh.intel.com:/lib/modules/
