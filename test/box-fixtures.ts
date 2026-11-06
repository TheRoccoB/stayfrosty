// Command output from a hardened box (captured from a live Ubuntu 26.04 box), used by the
// check and command tests.

export const SSHD_T_GOOD = `port 22
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
authenticationmethods publickey
allowusers ops
pubkeyauthentication yes
`;

export const UFW_GOOD = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
22/tcp (v6)                LIMIT IN    Anywhere (v6)

`;

export const SS_GOOD = `udp   UNCONN 0      0         127.0.0.54:53        0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=16))
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=14))
udp   UNCONN 0      0    192.0.2.10%eth0:68        0.0.0.0:*    users:(("systemd-network",pid=480,fd=23))
udp   UNCONN 0      0          127.0.0.1:323       0.0.0.0:*    users:(("chronyd",pid=13903,fd=4))
udp   UNCONN 0      0              [::1]:323          [::]:*    users:(("chronyd",pid=13903,fd=5))
tcp   LISTEN 0      4096      127.0.0.54:53        0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=17))
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=900,fd=3),("systemd",pid=1,fd=93))
tcp   LISTEN 0      4096            [::]:22           [::]:*    users:(("sshd",pid=900,fd=4),("systemd",pid=1,fd=94))
`;

export const APT_CONFIG_GOOD = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=\${distro_id},archive=\${distro_codename}-security";
Unattended-Upgrade::Origins-Pattern:: "origin=cloudflared,codename=any";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
`;

export const POLICY_GOOD = `cloudflared:
  Installed: 2026.9.3
  Candidate: 2026.9.3
  Version table:
 *** 2026.9.3 500
        500 https://pkg.cloudflare.com/cloudflared any/main amd64 Packages
        100 /var/lib/dpkg/status
     2026.9.2 500
        500 https://pkg.cloudflare.com/cloudflared any/main amd64 Packages
`;

// `sshd -T -C user=backupuser,host=x,addr=127.0.0.1` on Ubuntu 24.04 (OpenSSH 9.6) with the
// drop-in frosty renders for one restricted user (captured from a local test container).
export const SSHD_T_RESTRICTED = `
port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
logingracetime 120
x11displayoffset 10
maxauthtries 6
maxsessions 10
clientaliveinterval 0
clientalivecountmax 3
requiredrsasize 1024
streamlocalbindmask 0177
unusedconnectiontimeout none
permitrootlogin no
ignorerhosts yes
ignoreuserknownhosts no
hostbasedauthentication no
hostbasedusesnamefrompacketonly no
pubkeyauthentication yes
kerberosauthentication no
kerberosorlocalpasswd yes
kerberosticketcleanup yes
gssapiauthentication no
gssapicleanupcredentials yes
gssapikeyexchange no
gssapistrictacceptorcheck yes
gssapistorecredentialsonrekey no
gssapikexalgorithms gss-group14-sha256-,gss-group16-sha512-,gss-nistp256-sha256-,gss-curve25519-sha256-,gss-group14-sha1-,gss-gex-sha1-
passwordauthentication no
kbdinteractiveauthentication no
printmotd no
printlastlog yes
x11forwarding no
x11uselocalhost yes
permittty no
permituserrc no
strictmodes yes
tcpkeepalive yes
permitemptypasswords no
compression yes
gatewayports no
usedns no
allowtcpforwarding no
allowagentforwarding no
disableforwarding no
allowstreamlocalforwarding no
streamlocalbindunlink no
fingerprinthash SHA256
exposeauthinfo no
debianbanner yes
pidfile /run/sshd.pid
modulifile /etc/ssh/moduli
xauthlocation /usr/bin/xauth
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
banner none
forcecommand /usr/local/sbin/backup-gate
chrootdirectory none
trustedusercakeys none
revokedkeys none
securitykeyprovider internal
authorizedprincipalsfile none
versionaddendum none
authorizedkeyscommand none
authorizedkeyscommanduser none
authorizedprincipalscommand none
authorizedprincipalscommanduser none
hostkeyagent none
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
casignaturealgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
hostbasedacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
hostkeyalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
loglevel INFO
syslogfacility AUTH
authorizedkeysfile /etc/ssh/authorized_keys/%u
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
allowusers ops
allowusers backupuser
acceptenv LANG
acceptenv LC_*
authenticationmethods publickey
channeltimeout none
subsystem sftp /usr/lib/openssh/sftp-server 
maxstartups 10:30:100
persourcemaxstartups none
persourcenetblocksize 32:128
permittunnel no
ipqos lowdelay throughput
rekeylimit 0 0
permitopen any
permitlisten any
permituserenvironment no
pubkeyauthoptions none
`;

export const RESTRICTED_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER backup-puller-t1";
export const RESTRICTED_KEY_2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi other-t1";

// The forced command and every directory above it, as restrictedGatherScript prints them.
export const COMMAND_STAT_GOOD = `/usr/local/sbin/backup-gate root root 755 regular file
/usr/local/sbin root root 755 directory
/usr/local root root 755 directory
/usr root root 755 directory
/ root root 755 directory
`;
export const COMMAND_STAT_MISSING = COMMAND_STAT_GOOD.replace("/usr/local/sbin/backup-gate root root 755 regular file", "stat: cannot statx '/usr/local/sbin/backup-gate': No such file or directory");
