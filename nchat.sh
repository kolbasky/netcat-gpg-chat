#!/bin/bash

set -o pipefail

# THIS SCRIPT WAS TESTED ON ROCKY Linux 9.
# nc version is - Ncat 7.92 ( https://nmap.org/ncat )
# Since there are several flavors of ncat, some of them won't work as expected

usage() {
    cat << EOF
🔐 Secure Bash Chat with GPG E2EE

Usage: $0 <your_nickname> <partner_host:port>

Arguments:
  your_nickname         Your display name in chat.
                        Also this name is used to look up/create gpg key.
  partner_host:port     Partner's address and port to connect to.
                        This port is also used as listen port on your host.

Requirements:
  • Bash 4+ (for /dev/tcp)
  • GnuPG 2.1+ (gpg, gpg-agent)
  • Ncat 7.x (nmap's netcat with -k flag)
  • base64, timeout, mkfifo

EOF

    exit 1
}

username=$1
endpoint=$2
host=$(echo $endpoint | cut -d: -f1)
port=$(echo $endpoint | cut -d: -f2)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $# -ne 2 ]] || [[ ! "$endpoint" =~ ^[A-Za-z0-9._-]+:[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
    usage
fi

# remember screen contents to exit later gracafully
tput smcup && clear
# on exit restore screen contents
trap "tput rmcup; tput sgr0; exit 0;" EXIT

# temporary file to hold partner's user key during handshake
publickeyfile=$(mktemp 2>/dev/null || echo "/tmp/temp_$$_${RANDOM}${RANDOM}${RANDOM}")
trap "tput rmcup; tput sgr0; rm -f \"$publickeyfile\"; exit 0;" EXIT
# we listen for partner's key, write it to tempfile and import
handshake() {
    nc -l $port | base64 -d > "${publickeyfile}"
    partner_key=$(gpg --import "${publickeyfile}" 2>&1 | grep 'gpg: key' | grep -Eo '".*"' | tr -d '"')
}
# do it in background
handshake &
handshake_pid=$!

if [[ $( gpg --list-secret-keys $username 2> /dev/null | grep -c "^sec" ) -lt 1 ]]; then
    echo "⚠️  No GPG key found. Creating one..."
    gpg --quick-generate-key --pinentry-mode=loopback $username
fi

# try to send our public key to client
echo -n "Waiting for partner $host:$port to become online"
until (timeout 15 gpg --armor --export $(gpg --list-secret-keys --with-colons $username | grep "^sec" | head -1 | cut -d: -f5) | base64 -w 0 | nc -w 3 $host $port) 2>/dev/null; do
  echo -n "."
  sleep 1;
done
echo ""
# wait for other part's public key - script won't run further until handshake finishes
wait ${handshake_pid}

# import key and ask to user confirm it
partner_key=$(gpg --import "${publickeyfile}" 2>&1 | grep 'gpg: key' | grep -Eo '".*"' | tr -d '"')
if [[ -z $partner_key ]]; then
    read -p "Enter partner's Key ID (email or fingerprint): " partner_key
fi
echo "🔒 Contact your partner over some other channel and compare your keys! It is important to prevent MITM attacks!"
echo "🔒 ${partner_key}'s key is: $(gpg --list-keys $partner_key | head -2 | tail -1 | xargs)"
echo "🔒 Your public key is: $(gpg --list-keys $username | head -2 | tail -1 | xargs)"
user_confirm=""
until [[ "$user_confirm" =~ ^[YyNn]$ ]]; do
    read -n1 -p "Is this correct? (y/n): " user_confirm
    echo ""
done
if [[ "$user_confirm" =~ ^[Nn]$ ]]; then
    echo "It is not secure to continue, if keys do not match. Exiting!"
    exit 255
fi
echo "✅ Partner key ready. Starting chat..."
echo ""

echo ""
echo "🔑 Enter your passphrase once (cached by gpg-agent):"
until echo test | gpg --encrypt --armor --recipient $username | gpg --decrypt --pinentry-mode=loopback &>/dev/null; do
  echo "🔑 Enter your passphrase once (cached by gpg-agent):"
done
echo "✅ Passphrase cached. Starting chat..."
echo ""
rm -f "$publickeyfile"

# we can use file but this way is more secure - no history on disk
chatpipe=$(mktemp || echo "/tmp/temp_$$_${RANDOM}${RANDOM}${RANDOM}")
rm -f ${chatpipe}
mkfifo -m 600 "$chatpipe"

# previous nc has already exited the port is free
nc -k -l $port > "$chatpipe" &
NC_PID=$!
# cleanup after ourselves
trap "kill $NC_PID; rm -f \"$chatpipe\" \"$publickeyfile\"; tput rmcup; tput sgr0; exit 0;" EXIT

send_msg() {
    encrypted=$(echo "${username}: $3" | gpg --encrypt --sign --armor --recipient "$partner_key" --local-user "$username" --trust-model always 2>/dev/null)
    echo -e "$encrypted" | base64 -w 0 | nc -w 5 $host $port
    echo "" | nc -w 5 $host $port
    echo -ne "${BLUE}[$(date +%T)]${NC}${username}: "
}

receive_msg() {
    while read incoming_msg < "$chatpipe"; do
        decoded=$(echo "$incoming_msg" | base64 -d 2>/dev/null)
        decrypted=$(echo "$decoded" | gpg --decrypt --pinentry-mode=loopback 2>/dev/null)
        if [[ -n "$decrypted" ]]; then
            echo -ne "\n${GREEN}[$(date +%T)]${NC}${decrypted}"
            echo -ne "\n${BLUE}[$(date +%T)]${NC}${username}: "
        else
            echo -ne "\n${RED}[$(date +%T)] Failed to decrypt message or message is empty${NC}: $incoming_msg"
            echo -ne "\n${BLUE}[$(date +%T)]${NC}${username}: "
        fi
    done
}
echo -ne "${BLUE}[$(date +%T)]${NC}${username}: "
# run receiving process in background
receive_msg &

while :; do
    read message
    send_msg "${host}" "${port}" "${message}"
    sleep 0.1
done
