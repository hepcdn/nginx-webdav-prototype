#!/bin/bash
# Options from:
# https://github.com/hepcdn/nginx-webdav-prototype/blob/main/nginx/docker-entrypoint.sh

export USE_SSL=true
export SSL_HOST_CERT=/etc/grid-security/hostcert-xrootd.pem
export SSL_HOST_KEY=/etc/grid-security/hostkey-xrootd.pem
export SERVER_NAME=xrootd-se30-vanderbilt.sites.opensciencegrid.org
export PORT=1095

while : ; do
	apptainer pull -F docker://ghcr.io/hepcdn/nginx-webdav:latest
	#
	# By default, this script uses /tmp/hepcdn as the storage location.
	# If your test host has /store mounted, you can instead use
	#
	#   -B /store/test/hepcdn:/var/www/webdav
  #
	# .. which will bind-mount that subtree into the container. Do NOT bind-mount
  # the entire /store tree into the container, since the ACL setup is currently
  # minimal.
	# 	
	apptainer run \
	  --writable-tmpfs \
    -B /tmp/hepcdn:/var/www/webdav \
	  -B /etc/grid-security:/etc/grid-security:ro \
	  docker://ghcr.io/$hepcdn/nginx-webdav:latest &
	PID=$!
	PGID=$(< /proc/${PID}/stat sed -n '$s/.*) [^ ]* [^ ]* \([^ ]*\).*/\1/p')
	echo "Container running, PID=$PID, PGID=$PGID"
	TWELVE_HOURS_IN_15_SEC_INTERVAL=2880
	EXIT_CODE=-1
	for (( i=0 ; i<${TWELVE_HOURS_IN_15_SEC_INTERVAL}; ++i )); do
		kill -0 $PID &>/dev/null
		if [ $? -ne 0 ]; then
			wait $PID
			EXIT_CODE=$?
			echo "Container terminated, exit code: ${EXIT_CODE}"
			break
		fi
		sleep 15
	done
	if [ $EXIT_CODE -eq -1 ]; then
		echo "Restarting gracefully to pick up new image"
	fi
	kill -s QUIT -${PGID}
	wait $PID

	echo "Container restarting"
	sleep 5
done
