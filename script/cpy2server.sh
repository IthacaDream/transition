#!/bin/bash
## by will song
## upload the project to server
# -h for help

if [ "$1" = "-h" ]; then
cat <<HELP
    usage: $0 [local_work_dir] [remote_work_dir] [server_user]
HELP
    exit 0
fi

WORK_DIR="$1"
REMOTE_DIR="$2"
USER="$3"

#servers
SERVERS=("192.168.4.12" "192.168.4.10" "192.168.4.11")

[ -n "$1" ] || WORK_DIR="."
[ -n "$2" ] || REMOTE_DIR="~/work/transition/"
[ -n "$3" ] || USER="root"

echo "local work dir: ${WORK_DIR}"
echo "remote work dir: ${REMOTE_DIR}"
echo "user: ${USER}"

for svr in ${SERVERS[@]}
do
    echo scp -r $WORK_DIR ${USER}@${srv}:$REMOTE_DIR
    scp -r $WORK_DIR ${USER}@${svr}:$REMOTE_DIR
    echo "cp to server $s, DONE"
done
echo "all done"
