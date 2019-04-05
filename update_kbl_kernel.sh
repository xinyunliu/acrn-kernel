sudo rsync  -avz woliu@dp7.sh.intel.com:/home/woliu/Work/eb_native/out/sos_rootfs/lib/modules/* /lib/modules/
sudo mount /dev/sda1 /boot
md5sum /boot/EFI/org.xyl/bzImage
sudo cp /boot/EFI/org.xyl/bzImage /boot/EFI/org.xyl/bzImage.`date +%b-%d-%H%M`
sudo scp woliu@dp7.sh.intel.com:/home/woliu/Work/eb_native/out/sos_kernel/arch/x86/boot/bzImage /boot/EFI/org.xyl/
md5sum /boot/EFI/org.xyl/bzImage

