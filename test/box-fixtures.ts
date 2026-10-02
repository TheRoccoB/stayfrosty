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
