#!/bin/bash
# Change the following N lines per your env
workdir=/home/bockjoo/opt/cmsio2/cms/services/T2/ops/Work/ContainerCMSIO
SERVER_NAME=cmsio9.rc.ufl.edu
PORT=2811
server_local_disk=/opt/cms/etc # for the host certificate/key owned by the user running the podman
site_storage_topdir=/cmsuf # or put $workdir/nginx-webdav/data
# Change the above N lines per your env
if [ $(/bin/hostname -s) != $(echo $SERVER_NAME | cut -d. -f1) ] ; then
   echo ERROR: Change the lines 3-5 of the script per your env
   exit 1
fi
cd $workdir

git clone https://github.com/hepcdn/nginx-webdav.git    

cd nginx-webdav

# Backup the original entry point
/bin/cp -pR nginx/docker-entrypoint.sh nginx/docker-entrypoint.sh.original
# and update the entry point per your server and port
sed -i "/Set defaults/a SERVER_NAME=$SERVER_NAME\nPORT=$PORT" docker-entrypoint.sh
#podman build -t nginx-webdav -f nginx/nginx.dockerfile ./nginx
image_id=$(podman images | grep nginx_webdav | awk '{print $3}')
[ "x$image_id" == "x" ] || podman image rm $image_id
buildah bud -f nginx/nginx.dockerfile -t nginx_webdav ./nginx

#%%bash
mkdir data
echo 'Hello, world!' > data/hello.txt
#This works without --network=host
podman run -d --rm -p 2811:2811 --name nginx_webdav\
   -v ./nginx/conf.d:/etc/nginx/conf.d:Z \
   -v ./nginx/lua:/etc/nginx/lua:Z \
   -v ./data:/var/www/webdav:Z \
    --cgroup-manager=cgroupfs --tmpfs /tmp \
    --tmpfs /run \
               -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
               -v ${server_local_disk}/grid-security/grid-mapfile:/etc/grid-security/grid-mapfile:rw \
               -v ${server_local_disk}/grid-security/ban-mapfile:/etc/grid-security/ban-mapfile:rw \
               -v ${server_local_disk}/grid-security/voms-mapfile:/etc/grid-security/voms-mapfile:rw \
               -v ${server_local_disk}/grid-security/hostcert.pem:/etc/grid-security/hostcert.pem:rw \
               -v ${server_local_disk}/grid-security/hostkey.pem:/etc/grid-security/hostkey.pem:rw \
               -v ${server_local_disk}/grid-security/xrd/:/etc/grid-security/xrd:rw \
               -v ${server_local_disk}/sysconfig/xrootd:/etc/sysconfig/xrootd:rw \
               -v ${server_local_disk}/hosts:/etc/hosts:rw \
               -v ${server_local_disk}/hostname:/etc/hostname:rw \
               -v ${server_local_disk}/systemd/system/systemd-hostnamed.service.d/:/etc/systemd/system/systemd-hostnamed.service.d/:rw \
               -v ${server_local_disk}/selinux/config:/etc/selinux/config:rw \
               -v ${site_storage_topdir}/:${site_storage_topdir}/:rw \
               --systemd=true \
               --cgroup-manager=systemd \
   -e DEBUG=true \
   nginx_webdav
