make olddefconfig O=/home/woliu/Work/eb_native/out/sos_kernel &&  make O=/home/woliu/Work/eb_native/out/sos_kernel -j`nproc` &&  make modules_install INSTALL_MOD_PATH=/home/woliu/Work/eb_native/out/sos_rootfs O=/home/woliu/Work/eb_native/out/sos_kernel -j`nproc`

