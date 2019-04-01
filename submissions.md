## Building OPTEE
1. Build as normal 
   * see: https://optee.readthedocs.io/building/gits/build.html#get-and-build-the-solution
   * Steps 1-5 are needed

2. go to <OPTEE>/build and
    ``make QEMU_VIRTFS_ENABLE=y QEMU_USERNET_ENABLE=y QEMU_VIRTFS_HOST_DIR=/tmp/tee_share HOSTFWD=",hostfwd=tcp::1443-:1443" run-only``



3. Create working directories
   * mkdir -p <OPTEE>/projects
   * mkdir /tmp/tee_shared
   * mount -t 9p -o trans=virtio host /mnt

## Assumptions
    * all projects are located in <OPTEE>/projects
    * I'm using QEMUv8
    * TA instaluje sie do /lib/optee_armtz/

## Diff with needed changes to OPTEE
--- a/common.mk
+++ b/common.mk
@@ -34,8 +34,10 @@ CCACHE ?= $(shell which ccache) # Don't remove this comment (space is needed)
 # # Set QEMU_VIRTFS_ENABLE to 'y' and adjust QEMU_VIRTFS_HOST_DIR
 # # Then in QEMU, run:
 # # $ mount -t 9p -o trans=virtio host <mount_point>
-QEMU_VIRTFS_ENABLE             ?= n
-QEMU_VIRTFS_HOST_DIR   ?= $(ROOT)
+QEMU_VIRTFS_ENABLE             ?= y
+QEMU_VIRTFS_HOST_DIR   ?= /tmp/
+QEMU_USERNET_ENABLE     ?= y
+QEMU_PORT_FWD           ?= "hostfwd=tcp::1443-:1443"
 
 ################################################################################
 # Mandatory for autotools (for specifying --host)
@@ -343,7 +345,7 @@ define run-help
        @echo
 endef
 
-# Note: Using the LAUNCH_TERMINAL environment variable, it is not currently possible to set 
+# Note: Using the LAUNCH_TERMINAL environment variable, it is not currently possible to set
 # different titles for the terminals because there is no any common way among all the terminals

 