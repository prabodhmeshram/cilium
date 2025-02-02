#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

sudo iptables -P FORWARD ACCEPT
sudo ip6tables -P FORWARD ACCEPT

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
"${PROVISIONSRC}"/wait-cilium.sh
