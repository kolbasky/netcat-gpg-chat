# bash-secure-chat
> stupid idea. works anyway.<br>

end-to-end encrypted chat in pure bash. because why not.<br>
## 🔐 what it does
- auto GPG generation and key exchange on first connect
- fingerprint verification (prevents MITM)
- messages encrypted with GPG before they leave your machine
- doesn't store any history

## 📦 requirements
- bash >= 4
- gnupg >= 2.1
- nmap-ncat
- base64, mkfifo

## 🚀 usage
both users run
```
./nchat.sh UserName partner-address:port
```
follow the prompts. verify fingerprints when asked. chat.

## ⚠️ notes
- the port you specify is used for both listening and connecting
- IPs and the fact of communication are visible to your ISP. contents of messages are not.
- chats are not saved
- Creedence is cool
- if you skip fingerprint verification, MITM is possible.
- nc -k is required. if your nc doesn't have it, install nmap-ncat.
