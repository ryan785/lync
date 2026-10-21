# Checks reference

<!-- Generated from the check catalog by `go run ./internal/checks/gendoc`; do not edit by hand. -->

Every non-CVE check Lync runs. The ID is the prefix of every finding the check emits (`web:sensitive-file` -> `web:sensitive-file:/var/www/site/.env`), so it is what you put in `rules.disable` / `rules.enable`; `pack:<name>` and `tag:<tag>` toggle whole packs or tags. `lync checks` lists them with their state under your config and `lync checks --explain ID` shows the probe, expectation, remediation and references.

Severity is the typical/maximum; some checks adjust it with context. Level is the minimum `rules.level` (basic, medium, strict) at which a check runs. "opt-in" checks run only when listed in `rules.enable`. "Applies if" is the gate: a check whose gate doesn't match the host is reported as not applicable, never as a finding.

## Summary

| Pack | Checks | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|---|
| access | 7 | 2 | 3 | 2 | 0 | 0 |
| accounts | 13 | 2 | 2 | 3 | 6 | 0 |
| apache | 17 | 1 | 4 | 6 | 6 | 0 |
| audit | 21 | 0 | 0 | 1 | 20 | 0 |
| boot | 10 | 2 | 3 | 2 | 2 | 1 |
| bruteforce | 8 | 0 | 1 | 5 | 2 | 0 |
| containers | 11 | 4 | 6 | 1 | 0 | 0 |
| cron | 13 | 3 | 2 | 3 | 5 | 0 |
| devops | 12 | 3 | 8 | 1 | 0 | 0 |
| dns | 14 | 0 | 5 | 4 | 5 | 0 |
| docker | 21 | 2 | 7 | 5 | 7 | 0 |
| elasticsearch | 13 | 0 | 9 | 4 | 0 | 0 |
| eol | 4 | 0 | 2 | 2 | 0 | 0 |
| etcd | 4 | 0 | 2 | 2 | 0 | 0 |
| exposure | 7 | 0 | 3 | 2 | 2 | 0 |
| fileshare | 11 | 0 | 6 | 3 | 2 | 0 |
| filesystem | 18 | 0 | 9 | 4 | 5 | 0 |
| firewall | 15 | 0 | 7 | 5 | 3 | 0 |
| ftp | 13 | 0 | 6 | 5 | 2 | 0 |
| hardening | 41 | 0 | 1 | 18 | 22 | 0 |
| influxdb-cassandra | 4 | 0 | 2 | 1 | 1 | 0 |
| kubernetes | 14 | 4 | 4 | 3 | 3 | 0 |
| logging | 11 | 0 | 0 | 2 | 9 | 0 |
| login-defs | 11 | 0 | 1 | 2 | 8 | 0 |
| mac | 9 | 0 | 0 | 5 | 4 | 0 |
| mail | 16 | 4 | 3 | 5 | 4 | 0 |
| memcached | 2 | 0 | 1 | 1 | 0 | 0 |
| modules | 15 | 0 | 0 | 3 | 12 | 0 |
| mongodb | 7 | 0 | 3 | 3 | 1 | 0 |
| monitoring | 18 | 0 | 6 | 8 | 4 | 0 |
| mount | 15 | 0 | 0 | 9 | 6 | 0 |
| mysql | 25 | 1 | 9 | 7 | 8 | 0 |
| network | 1 | 0 | 0 | 1 | 0 | 0 |
| nginx | 16 | 2 | 3 | 4 | 7 | 0 |
| pam | 11 | 1 | 1 | 2 | 7 | 0 |
| php | 32 | 0 | 7 | 9 | 16 | 0 |
| php-fpm | 10 | 2 | 4 | 1 | 3 | 0 |
| postgresql | 15 | 1 | 6 | 5 | 3 | 0 |
| rabbitmq | 5 | 0 | 4 | 1 | 0 | 0 |
| redis | 10 | 0 | 5 | 4 | 1 | 0 |
| remote-admin | 13 | 1 | 7 | 4 | 1 | 0 |
| runtimes | 18 | 3 | 5 | 5 | 5 | 0 |
| secrets | 9 | 0 | 4 | 3 | 2 | 0 |
| services-legacy | 19 | 0 | 3 | 4 | 11 | 1 |
| snmp | 5 | 0 | 1 | 3 | 1 | 0 |
| ssh | 33 | 4 | 4 | 12 | 13 | 0 |
| sudo | 14 | 1 | 3 | 4 | 6 | 0 |
| suid | 5 | 3 | 2 | 0 | 0 | 0 |
| system | 8 | 0 | 3 | 4 | 1 | 0 |
| time | 6 | 0 | 0 | 2 | 4 | 0 |
| tls | 9 | 0 | 5 | 2 | 2 | 0 |
| tomcat | 13 | 1 | 7 | 3 | 2 | 0 |
| vpn | 15 | 0 | 6 | 3 | 6 | 0 |
| web-exposure | 9 | 0 | 5 | 3 | 1 | 0 |
| web-server | 2 | 0 | 2 | 0 | 0 | 0 |
| webapps | 26 | 2 | 13 | 9 | 2 | 0 |
| **total** | **724** | 49 | 215 | 215 | 243 | 2 |

## Go rule (`access`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `account:ssh-perms` | High | - | ~/.ssh or authorized_keys writable by group/others or owned by another user | - |
| `account:sudo-nopasswd` | Medium | - | sudoers grants NOPASSWD (ALL = High) | - |
| `cron:writable-script` | Critical | - | Root cron job runs a script that non-root users can modify | - |
| `docker:group-members` | Medium | - | Users in the docker group (root-equivalent) | - |
| `docker:socket-perms` | Critical | - | docker.sock writable by non-root users outside the docker group | - |
| `fs:world-writable-dir` | High | - | World-writable directory (no sticky bit) under /etc, web roots or cron dirs | - |
| `secrets:world-readable` | High | - | Password/token-like keys in world-readable systemd units, compose files or .env files (key names only) | - |

## Local accounts and groups (`accounts`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `account:empty-pwd` | Critical | - | Account with an empty password hash | - |
| `account:gid0-group` | Medium | medium | Group other than root has GID 0 | always |
| `account:inactive-default` | Low | strict | Accounts are never disabled after password expiry | always |
| `account:nis-plus-entry` | Medium | medium | Legacy '+' NIS entry in an account database | always |
| `account:no-max-age` | Low | strict | Password never expires for an account with a password | always |
| `account:nologin-in-shells` | Low | strict | nologin is listed in /etc/shells | always |
| `account:passwd-hash` | High | medium | Password hash stored in world-readable /etc/passwd | always |
| `account:root-primary-group` | Low | strict | Non-system account has root (GID 0) as its primary group | always |
| `account:shadow-group-members` | Medium | medium | Users are members of the shadow group | always |
| `account:shell-timeout` | Low | strict | No idle shell timeout (TMOUT) configured | always |
| `account:system-login-shell` | Low | strict | System account has an interactive login shell | always |
| `account:uid0` | Critical | - | Non-root account with UID 0 | - |
| `account:weak-hash` | High | medium | Account password uses an obsolete hash (MD5 or DES) | always |

## Apache httpd (`apache`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `apache:allowoverride-root` | Low | medium | Apache allows .htaccess overrides at the filesystem root | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:conf-not-root-owned` | Medium | medium | Apache configuration owned by a non-root user | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:conf-world-writable` | High | medium | Apache configuration writable by any user | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:documentroot-dangerous` | Critical | basic | Apache serves a system directory as DocumentRoot | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:fileetag-inode` | Low | strict | Apache ETags include inode numbers | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:htpasswd-weak-hash` | Medium | medium | Apache basic-auth file uses weak or plain-text password hashes | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:htpasswd-world-readable` | Medium | medium | Apache basic-auth password file readable by any user | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:insecure-renegotiation` | High | medium | Apache allows insecure TLS renegotiation | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:log-world-readable` | Low | strict | Apache log files readable by any user | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:no-reqtimeout` | Low | strict | Apache mod_reqtimeout is not loaded (Slowloris) | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:open-proxy` | High | medium | Apache acts as a forward proxy (ProxyRequests On) | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:root-dir-not-denied` | Medium | medium | Apache does not deny access to the filesystem root | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf); file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf |
| `apache:ssl-compression` | Medium | medium | Apache TLS compression enabled (CRIME) | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:status-info-public` | High | medium | Apache server-status or server-info open to everyone | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:userdir-enabled` | Low | medium | Apache UserDir serves users' home directories | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:weak-ssl-cipher` | Medium | medium | Apache allows weak TLS cipher suites | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |
| `apache:webdav-enabled` | Low | medium | Apache WebDAV enabled | (package httpd\|apache2 or file /etc/httpd/conf/httpd.conf\|/etc/apache2/apache2.conf) |

## Linux audit framework (auditd) (`audit`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `audit:admin-space-left-action` | Low | strict | auditd keeps running when audit disk space is critically low | package audit\|auditd |
| `audit:backlog-limit` | Low | strict | Audit backlog limit is not raised at boot | package audit\|auditd |
| `audit:boot-param` | Low | strict | Processes started before auditd are not audited (no audit=1) | package audit\|auditd |
| `audit:disk-error-action` | Low | strict | auditd ignores disk write errors | package audit\|auditd |
| `audit:disk-full-action` | Low | medium | auditd keeps running silently when its disk is full | package audit\|auditd |
| `audit:immutable` | Low | strict | Audit rules are not locked (-e 2) | package audit\|auditd |
| `audit:installed` | Low | medium | auditd is not installed | always |
| `audit:max-log-file-action` | Low | strict | auditd rotates away old audit logs | package audit\|auditd |
| `audit:not-enabled` | Low | medium | auditd is not enabled at boot | package audit\|auditd |
| `audit:not-running` | Medium | medium | auditd is installed but not running | package audit\|auditd |
| `audit:rule-delete` | Low | strict | File deletions by users are not audited | package audit\|auditd |
| `audit:rule-identity` | Low | medium | Changes to account databases are not audited | package audit\|auditd |
| `audit:rule-logins` | Low | strict | Login and lockout records are not audited | package audit\|auditd |
| `audit:rule-mac-policy` | Low | strict | Changes to SELinux/AppArmor policy are not audited | package audit\|auditd |
| `audit:rule-modules` | Low | medium | Kernel module loading is not audited | package audit\|auditd |
| `audit:rule-mounts` | Low | strict | Filesystem mounts by users are not audited | package audit\|auditd |
| `audit:rule-perm-mod` | Low | strict | Permission and ownership changes are not audited | package audit\|auditd |
| `audit:rule-session` | Low | strict | Session records (utmp/wtmp/btmp) are not audited | package audit\|auditd |
| `audit:rule-sudoers` | Low | medium | Changes to sudoers are not audited | package audit\|auditd |
| `audit:rule-time-change` | Low | strict | System time changes are not audited | package audit\|auditd |
| `audit:space-left-action` | Low | strict | auditd does not alert when audit disk space runs low | package audit\|auditd |

## Bootloader and kernel command line (`boot`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `boot:apparmor-disabled-cmdline` | High | medium | AppArmor disabled on the kernel command line | always |
| `boot:boot-writable` | Critical | basic | /boot is writable by non-root users | always |
| `boot:grub-cfg-readable` | Low | strict | GRUB configuration is readable by all users | always |
| `boot:grub-cfg-writable` | Critical | basic | GRUB configuration is writable by non-root users | always |
| `boot:grub-no-password` | Low | strict | GRUB has no bootloader password | file /boot/grub2/grub.cfg\|/boot/grub/grub.cfg |
| `boot:grub-user-cfg-perms` | Medium | medium | GRUB password file (user.cfg) is readable by other users | always |
| `boot:init-override` | High | medium | Kernel booted with init= pointing at a shell | always |
| `boot:mitigations-off` | Medium | medium | CPU vulnerability mitigations disabled on the kernel command line | always |
| `boot:secure-boot-disabled` | Info | strict | UEFI Secure Boot is disabled | binary mokutil |
| `boot:selinux-disabled-cmdline` | High | medium | SELinux disabled or permissive on the kernel command line | always |

## Brute-force protection (fail2ban, sshguard, CrowdSec) (`bruteforce`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `crowdsec:lapi-public` | Medium | medium | CrowdSec local API listens beyond localhost | package crowdsec |
| `crowdsec:no-bouncer` | Low | medium | CrowdSec has no bouncer package installed | package crowdsec |
| `crowdsec:not-running` | Medium | medium | CrowdSec is installed but not running | package crowdsec |
| `fail2ban:ignoreip-any` | High | medium | fail2ban ignores every address | package fail2ban\|fail2ban-server |
| `fail2ban:maxretry-high` | Low | medium | fail2ban allows many attempts before banning | package fail2ban\|fail2ban-server |
| `fail2ban:no-sshd-jail` | Medium | medium | fail2ban runs without an SSH jail | active fail2ban; process sshd |
| `fail2ban:not-running` | Medium | medium | fail2ban is installed but not running | package fail2ban\|fail2ban-server |
| `sshguard:not-running` | Medium | medium | sshguard is installed but not running | package sshguard |

## Podman, containerd and CRI-O (`containers`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `containerd:config-perms` | High | medium | containerd configuration is writable by non-root users | file /etc/containerd/config.toml |
| `containerd:grpc-tcp` | High | medium | containerd gRPC API is exposed over TCP | file /etc/containerd/config.toml |
| `containerd:socket-perms` | Critical | medium | containerd socket is writable by non-root users | file /run/containerd/containerd.sock |
| `crio:socket-perms` | Critical | medium | CRI-O socket is writable by non-root users | file /var/run/crio/crio.sock\|/run/crio/crio.sock |
| `podman:container-dangerous-caps` | High | medium | Podman container {name} adds dangerous capabilities ({cap_add}) | binary podman |
| `podman:container-host-network` | Medium | medium | Podman container {name} uses the host network namespace | binary podman |
| `podman:container-host-pid` | High | medium | Podman container {name} shares the host PID namespace | binary podman |
| `podman:container-privileged` | High | medium | Podman container {name} runs privileged | binary podman |
| `podman:container-sensitive-mount` | High | medium | Podman container {name} bind-mounts a sensitive host directory | binary podman |
| `podman:container-socket-mount` | Critical | medium | Podman container {name} has a container-runtime socket mounted | binary podman |
| `podman:socket-perms` | Critical | medium | Rootful Podman API socket is writable by non-root users | file /run/podman/podman.sock |

## cron and at scheduling (`cron`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `cron:allow-missing` | Low | strict | cron is not restricted with cron.allow | file /etc/crontab\|/etc/cron.d |
| `cron:allow-perms` | Medium | medium | cron/at allow or deny list is writable by non-root users | always |
| `cron:at-allow-missing` | Low | strict | at is not restricted with at.allow | binary at |
| `cron:crontab-perms` | Critical | basic | /etc/crontab is writable by non-root users | always |
| `cron:crontab-readable` | Low | strict | /etc/crontab is readable by all users | always |
| `cron:d-file-perms` | Critical | basic | /etc/cron.d entry is writable by non-root users | always |
| `cron:daemon-inactive` | Low | strict | cron daemon installed but not running | always |
| `cron:dir-perms` | Critical | basic | cron directory is writable by non-root users | always |
| `cron:dir-readable` | Low | strict | cron directories are readable by all users | always |
| `cron:pipe-to-shell` | Medium | medium | Cron job pipes downloaded or decoded content into a shell | always |
| `cron:root-job-from-tmp` | High | medium | Root cron job runs something from a world-writable directory | always |
| `cron:spool-writable` | High | medium | cron spool directory is world-writable | always |
| `cron:user-crontab-perms` | Medium | medium | User crontab file is writable by other users | always |

## CI/CD and code hosting (Jenkins, GitLab, GitLab Runner, Gitea/Forgejo) (`devops`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `gitea:config-readable` | High | medium | Gitea/Forgejo app.ini {path} is readable by other users | file /etc/gitea/app.ini\|/etc/forgejo/app.ini |
| `gitea:install-unlocked` | Critical | basic | Gitea/Forgejo installer is not locked ({_key}) | file /etc/gitea/app.ini\|/etc/forgejo/app.ini |
| `gitea:open-registration` | Medium | medium | Gitea/Forgejo allows open self-registration ({_key}) | file /etc/gitea/app.ini\|/etc/forgejo/app.ini |
| `gitlab-runner:config-readable` | High | medium | GitLab Runner config.toml is readable by other users | file /etc/gitlab-runner/config.toml |
| `gitlab-runner:docker-socket-volume` | High | medium | GitLab Runner mounts the Docker socket into CI jobs | file /etc/gitlab-runner/config.toml |
| `gitlab-runner:privileged` | High | medium | GitLab Runner Docker executor runs jobs privileged | file /etc/gitlab-runner/config.toml |
| `gitlab:secrets-readable` | High | medium | GitLab secret file {path} is readable by other users | file /etc/gitlab |
| `jenkins:anonymous-read` | High | medium | Jenkins grants anonymous read access | file /var/lib/jenkins/config.xml |
| `jenkins:secret-files-readable` | High | medium | Jenkins secret {path} is readable by other users | file /var/lib/jenkins |
| `jenkins:security-disabled` | Critical | basic | Jenkins security is disabled | file /var/lib/jenkins/config.xml |
| `jenkins:signup-enabled` | High | medium | Jenkins allows users to sign up | file /var/lib/jenkins/config.xml |
| `jenkins:unsecured-authorization` | Critical | basic | Jenkins authorization allows anyone to do anything | file /var/lib/jenkins/config.xml |

## DNS servers (BIND, Unbound, dnsmasq) (`dns`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `bind:allow-transfer-any` | Medium | medium | BIND allows zone transfers to any host | package bind\|bind9 |
| `bind:dnssec-validation-off` | Medium | medium | BIND DNSSEC validation is disabled | package bind\|bind9 |
| `bind:named-as-root` | High | medium | named runs as root | process named |
| `bind:named-conf-writable` | High | medium | BIND configuration is writable by other users | package bind\|bind9 |
| `bind:no-rate-limit` | Low | strict | BIND has no response rate limiting | package bind\|bind9 |
| `bind:open-recursion` | High | basic | BIND allows recursion for any client | package bind\|bind9 |
| `bind:rndc-key-perms` | High | medium | BIND rndc key is readable by other users | package bind\|bind9 |
| `bind:version-disclosed` | Low | medium | BIND discloses its version (no version override) | package bind\|bind9 |
| `dnsmasq:no-domain-needed` | Low | strict | dnsmasq forwards plain names and private reverse lookups upstream | package dnsmasq |
| `dnsmasq:unrestricted-listener` | Medium | medium | dnsmasq answers DNS on every interface without restriction | package dnsmasq; port 53 |
| `unbound:identity-disclosed` | Low | strict | Unbound answers identity queries | package unbound |
| `unbound:open-resolver` | High | basic | Unbound allows recursion from any address | package unbound |
| `unbound:remote-control-public` | Medium | medium | Unbound remote control listens on all interfaces | package unbound |
| `unbound:version-disclosed` | Low | medium | Unbound answers version queries | package unbound |

## Docker Engine daemon and running containers (`docker`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `docker:api-exposed` | High | basic | Docker API listening on a network address ({_loc}) | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:container-dangerous-caps` | High | medium | Container {name} adds dangerous capabilities ({cap_add}) | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-host-ipc` | Medium | medium | Container {name} shares the host IPC namespace | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-host-network` | Medium | medium | Container {name} uses the host network namespace | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-host-pid` | High | medium | Container {name} shares the host PID namespace | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-no-memory-limit` | Low | strict | Container {name} has no memory limit | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-privileged` | High | basic | Container {name} runs privileged | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-root-user` | Low | strict | Container {name} runs as root | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-sensitive-mount` | High | medium | Container {name} bind-mounts a sensitive host directory | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-socket-mount` | Critical | basic | Container {name} has the container runtime socket mounted | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:container-unconfined` | Medium | medium | Container {name} runs with seccomp/AppArmor/SELinux confinement disabled | (binary docker\|dockerd or file /etc/docker/daemon.json); file /var/run/docker.sock\|/run/docker.sock |
| `docker:daemon-json-perms` | High | medium | /etc/docker/daemon.json is writable by non-root users | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:data-root-perms` | Medium | strict | Docker data root is accessible to other users | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:icc` | Low | strict | Inter-container communication allowed on the default bridge | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:insecure-registries` | Medium | medium | Docker trusts insecure (plain HTTP / unverified TLS) registries | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:live-restore` | Low | strict | Docker live-restore is disabled | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:log-rotation` | Low | medium | Container logs (json-file) are not rotated | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:no-new-privileges` | Low | strict | Containers may gain new privileges by default | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:tls-not-verified` | Critical | basic | Docker daemon accepts TCP connections without client-certificate verification | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:unit-file-perms` | High | medium | Docker systemd unit or drop-in is writable by non-root users | (binary docker\|dockerd or file /etc/docker/daemon.json) |
| `docker:userns-remap` | Low | strict | Docker user-namespace remapping is not enabled | (binary docker\|dockerd or file /etc/docker/daemon.json) |

## Elasticsearch / OpenSearch (`elasticsearch`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `elasticsearch:config-writable` | High | medium | Elasticsearch/OpenSearch configuration is world-writable | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml |
| `elasticsearch:cors-wildcard` | High | medium | Elasticsearch allows cross-origin requests from any site | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/elasticsearch/elasticsearch.yml |
| `elasticsearch:eol` | High | medium | Elasticsearch version is end-of-life | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml |
| `elasticsearch:http-ssl-disabled` | Medium | medium | Elasticsearch HTTP TLS is disabled on a non-local listener | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/elasticsearch/elasticsearch.yml |
| `elasticsearch:keystore-readable` | High | medium | elasticsearch.keystore is world-readable | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml |
| `elasticsearch:network-host-public` | Medium | medium | Elasticsearch listens beyond localhost | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/elasticsearch/elasticsearch.yml |
| `elasticsearch:security-disabled` | High | basic | Elasticsearch security (authentication) is disabled | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/elasticsearch/elasticsearch.yml |
| `opensearch:cors-wildcard` | High | medium | OpenSearch allows cross-origin requests from any site | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/opensearch/opensearch.yml |
| `opensearch:demo-certificates` | High | medium | OpenSearch uses the public demo certificates | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/opensearch/opensearch.yml |
| `opensearch:eol` | High | medium | OpenSearch 1.x is end-of-life | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml |
| `opensearch:http-ssl-disabled` | Medium | medium | OpenSearch HTTP TLS is disabled on a non-local listener | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/opensearch/opensearch.yml |
| `opensearch:network-host-public` | Medium | medium | OpenSearch listens beyond localhost | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/opensearch/opensearch.yml |
| `opensearch:security-disabled` | High | basic | OpenSearch security plugin is disabled | file /etc/elasticsearch/elasticsearch.yml\|/etc/opensearch/opensearch.yml; file /etc/opensearch/opensearch.yml |

## End-of-life language runtimes (installed packages) (`eol`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `eol` | High | - | OS release past or near end-of-life (endoflife.date) | - |
| `eol:java-legacy` | High | medium | End-of-life Java runtime installed ({name}) | always |
| `eol:nodejs-package` | Medium | medium | Node.js {upstream} package is past upstream end-of-life | not(os debian) |
| `eol:python2` | Medium | medium | Python 2 is installed ({name} {upstream}) | always |

## etcd (`etcd`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `etcd:client-cert-auth` | High | medium | etcd accepts remote clients without certificate authentication | file /etc/etcd/etcd.conf\|/etc/default/etcd |
| `etcd:client-plaintext-remote` | High | medium | etcd serves clients over plain HTTP on a non-loopback address | file /etc/etcd/etcd.conf\|/etc/default/etcd |
| `etcd:data-dir-perms` | Medium | medium | etcd data directory is accessible to other users | file /etc/etcd/etcd.conf\|/etc/default/etcd |
| `etcd:peer-plaintext` | Medium | medium | etcd peer traffic uses plain HTTP on a non-loopback address | file /etc/etcd/etcd.conf\|/etc/default/etcd |

## Go rule (`exposure`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `checkmk:unrestricted` | Medium | - | Checkmk agent (6556) answers anyone: no only_from restriction and no TLS agent controller | - |
| `cockpit:enabled` | Low | - | Cockpit web console socket is enabled | - |
| `docker:published-bypass` | High | - | Docker-published port on 0.0.0.0/:: while DOCKER-USER is empty: reachable regardless of firewalld | - |
| `firewall:stale-open` | Low | - | firewalld zone opens a port/service that nothing listens on | - |
| `net:datastore-exposed` | High | - | Database/cache port (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached...) listening on a non-loopback address | - |
| `net:rpcbind-exposed` | Medium | - | rpcbind (111) listening on a non-loopback address | - |
| `redis:no-auth` | High | - | Redis config without requirepass/ACL users | - |

## File sharing (Samba, NFS) (`fileshare`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `nfs:anonuid-root` | High | medium | NFS export maps anonymous users to root | package nfs-utils\|nfs-kernel-server |
| `nfs:insecure-ports` | Medium | medium | NFS export accepts requests from unprivileged ports | package nfs-utils\|nfs-kernel-server |
| `nfs:no-root-squash` | High | basic | NFS export trusts remote root (no_root_squash) | package nfs-utils\|nfs-kernel-server |
| `nfs:world-export` | High | basic | NFS export is open to every host | package nfs-utils\|nfs-kernel-server |
| `samba:guest-share` | Medium | medium | Samba share allows guest access | package samba\|samba-common\|samba-common-bin |
| `samba:guest-writable-share` | High | basic | Samba share is writable by guests | package samba\|samba-common\|samba-common-bin |
| `samba:lanman-auth` | High | medium | Samba accepts LANMAN authentication | package samba\|samba-common\|samba-common-bin |
| `samba:map-to-guest` | Low | medium | Samba maps failed logins to the guest account | package samba\|samba-common\|samba-common-bin |
| `samba:ntlmv1` | Medium | medium | Samba accepts NTLMv1 authentication | package samba\|samba-common\|samba-common-bin |
| `samba:signing-not-mandatory` | Low | strict | Samba does not require SMB signing | package samba\|samba-common\|samba-common-bin |
| `samba:smb1-enabled` | High | medium | Samba accepts SMB1 (NT1) | package samba\|samba-common\|samba-common-bin |

## Account database, home directory and system file permissions (`filesystem`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `fs:core-dump-limit` | Low | strict | Core dumps are not limited for all users | always |
| `fs:coredump-storage` | Low | strict | systemd-coredump stores core dumps on disk | file /usr/lib/systemd/systemd-coredump\|/lib/systemd/systemd-coredump |
| `fs:dotfile-world-writable` | High | medium | World-writable shell startup file in a home directory | always |
| `fs:group-perms` | High | basic | /etc/group has unsafe ownership or permissions | always |
| `fs:gshadow-perms` | High | medium | /etc/gshadow is readable or writable beyond root and the shadow group | always |
| `fs:home-world-readable` | Low | strict | Home directory readable by all users | always |
| `fs:home-world-writable` | High | medium | World-writable home directory | always |
| `fs:hosts-equiv` | Low | medium | /etc/hosts.equiv or /etc/ssh/shosts.equiv present | always |
| `fs:opasswd-perms` | Medium | medium | /etc/security/opasswd is readable by non-root users | always |
| `fs:passwd-backup-perms` | Medium | medium | Backup /etc/passwd- or /etc/group- is writable by non-root users | always |
| `fs:passwd-perms` | High | basic | /etc/passwd has unsafe ownership or permissions | always |
| `fs:rhosts-files` | Low | medium | .rhosts or .shosts file present | always |
| `fs:root-home-perms` | Medium | medium | /root is accessible to other users | always |
| `fs:shadow-backup-perms` | High | medium | Backup /etc/shadow- or /etc/gshadow- is readable beyond root and the shadow group | always |
| `fs:shadow-perms` | High | basic | /etc/shadow is readable or writable beyond root and the shadow group | always |
| `fs:tmp-sticky` | High | basic | World-writable temp directory without the sticky bit | always |
| `fs:unexpected-setuid` | Medium | - | Setuid binaries outside the baseline | - |
| `fs:world-writable` | High | - | World-writable files under /etc, /usr/local, /opt | - |

## Host firewall (firewalld, nftables, iptables, ufw) (`firewall`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `firewall:conflicting-managers` | Medium | medium | Another firewall service runs alongside firewalld | active firewalld |
| `firewall:firewalld-default-zone-trusted` | High | basic | firewalld default zone is "trusted" (accepts all traffic) | active firewalld |
| `firewall:firewalld-enabled-not-running` | High | basic | firewalld is enabled but not running | package firewalld |
| `firewall:firewalld-log-denied-off` | Low | strict | firewalld does not log denied packets | package firewalld |
| `firewall:firewalld-zone-drifting` | Medium | medium | firewalld AllowZoneDrifting is enabled | package firewalld |
| `firewall:firewalld-zone-target-accept` | High | medium | firewalld default zone target is ACCEPT | active firewalld |
| `firewall:ip6tables-input-open` | Medium | medium | IPv6 INPUT is unfiltered while an iptables service runs | active ip6tables\|netfilter-persistent; file /proc/net/if_inet6; not(active firewalld\|ufw) |
| `firewall:iptables-input-open` | High | medium | iptables service is active but INPUT accepts everything | active iptables\|netfilter-persistent; not(active firewalld\|ufw) |
| `firewall:nftables-empty` | High | medium | nftables.service is active but no ruleset is loaded | active nftables; not(active firewalld\|ufw) |
| `firewall:nftables-permissive-default` | Medium | medium | nftables runs the permissive default ruleset (no drop or reject) | active nftables; os debian; not(active firewalld\|ufw) |
| `firewall:none-active` | High | - | No active host firewall | - |
| `firewall:ufw-default-forward-accept` | Low | medium | ufw forwards routed traffic by default | package ufw |
| `firewall:ufw-default-incoming-allow` | High | medium | ufw is active with a default incoming policy of allow | package ufw |
| `firewall:ufw-ipv6-disabled` | Medium | medium | ufw does not manage IPv6 while IPv6 is enabled | package ufw; file /proc/net/if_inet6 |
| `firewall:ufw-logging-off` | Low | strict | ufw logging is off | package ufw |

## FTP servers (vsftpd, ProFTPD, Pure-FTPd) (`ftp`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `proftpd:anonymous` | High | basic | ProFTPD has an anonymous FTP section | package proftpd\|proftpd-basic\|proftpd-core |
| `proftpd:no-tls` | Medium | medium | ProFTPD does not enable TLS | package proftpd\|proftpd-basic\|proftpd-core |
| `proftpd:root-login` | High | medium | ProFTPD permits root logins | package proftpd\|proftpd-basic\|proftpd-core |
| `proftpd:server-ident` | Low | medium | ProFTPD advertises its version | package proftpd\|proftpd-basic\|proftpd-core |
| `pureftpd:anonymous` | High | medium | Pure-FTPd allows anonymous logins | package pure-ftpd\|pure-ftpd-common |
| `vsftpd:anonymous` | High | basic | vsftpd allows anonymous logins | package vsftpd |
| `vsftpd:anonymous-mkdir` | Medium | medium | vsftpd lets anonymous users create directories | package vsftpd |
| `vsftpd:anonymous-upload` | High | medium | vsftpd allows anonymous uploads | package vsftpd |
| `vsftpd:ftp-bounce` | Medium | medium | vsftpd allows FTP bounce (promiscuous PORT/PASV) | package vsftpd |
| `vsftpd:no-chroot` | Low | medium | vsftpd does not chroot local users | package vsftpd |
| `vsftpd:no-tls` | High | medium | vsftpd local logins without TLS | package vsftpd |
| `vsftpd:sslv3` | Medium | medium | vsftpd enables SSLv3/SSLv2 | package vsftpd |
| `vsftpd:tls-optional-for-logins` | Medium | medium | vsftpd lets local users log in without TLS even though TLS is enabled | package vsftpd |

## Kernel and network sysctl hardening (`hardening`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `hardening:dev.tty.ldisc_autoload` | Low | strict | Unprivileged users can autoload TTY line disciplines | always |
| `hardening:fs.protected_fifos` | Low | medium | FIFO protection disabled | always |
| `hardening:fs.protected_hardlinks` | Medium | medium | Hardlink protection disabled | always |
| `hardening:fs.protected_regular` | Low | medium | Regular-file protection in sticky directories disabled | always |
| `hardening:fs.protected_symlinks` | Medium | medium | Symlink protection disabled | always |
| `hardening:fs.suid_dumpable` | Low | medium | Setuid programs can produce core dumps | always |
| `hardening:kernel.core_uses_pid` | Low | strict | Core dump file names don't include the PID | always |
| `hardening:kernel.dmesg_restrict` | Medium | medium | Unprivileged users can read the kernel log | always |
| `hardening:kernel.kexec_load_disabled` | Low | basic | kexec_load is not disabled | always |
| `hardening:kernel.kptr_restrict` | Medium | medium | Kernel pointer addresses may leak | always |
| `hardening:kernel.modules_disabled` | Low | strict | Kernel modules can still be loaded | always |
| `hardening:kernel.perf_event_paranoid` | Low | medium | Unprivileged users can use perf events | always |
| `hardening:kernel.randomize_va_space` | High | basic | ASLR is not fully enabled | always |
| `hardening:kernel.sysrq` | Low | medium | Magic SysRq key fully enabled | always |
| `hardening:kernel.unprivileged_bpf_disabled` | Medium | basic | Unprivileged eBPF is enabled | always |
| `hardening:kernel.yama.ptrace_scope` | Medium | medium | Any process can ptrace other processes of the same user | always |
| `hardening:net.core.bpf_jit_harden` | Low | strict | BPF JIT hardening is off | always |
| `hardening:net.ipv4.conf.all.accept_redirects` | Medium | medium | ICMP redirects accepted | always |
| `hardening:net.ipv4.conf.all.accept_source_route` | Medium | medium | IPv4 source-routed packets accepted | always |
| `hardening:net.ipv4.conf.all.log_martians` | Low | medium | Martian packets are not logged | always |
| `hardening:net.ipv4.conf.all.rp_filter` | Medium | medium | Reverse-path filtering disabled | always |
| `hardening:net.ipv4.conf.all.secure_redirects` | Low | strict | Redirects from default gateways accepted | always |
| `hardening:net.ipv4.conf.all.send_redirects` | Low | medium | Host sends ICMP redirects | always |
| `hardening:net.ipv4.conf.default.accept_redirects` | Medium | medium | ICMP redirects accepted on new interfaces | always |
| `hardening:net.ipv4.conf.default.accept_source_route` | Medium | medium | IPv4 source routing accepted on new interfaces | always |
| `hardening:net.ipv4.conf.default.rp_filter` | Medium | medium | Reverse-path filtering disabled for new interfaces | always |
| `hardening:net.ipv4.conf.default.secure_redirects` | Low | strict | Redirects from default gateways accepted on new interfaces | always |
| `hardening:net.ipv4.conf.default.send_redirects` | Low | medium | New interfaces send ICMP redirects | always |
| `hardening:net.ipv4.icmp_echo_ignore_broadcasts` | Medium | medium | Host answers broadcast pings | always |
| `hardening:net.ipv4.icmp_ignore_bogus_error_responses` | Low | medium | Bogus ICMP error responses are logged | always |
| `hardening:net.ipv4.ip_forward` | Low | strict | IPv4 forwarding enabled | not((package docker-ce\|docker.io\|moby-engine\|podman\|containerd.io\|containerd\|kubelet\|k3s\|libvirt-daemon\|libvirt-daemon-system\|wireguard-tools\|openvpn\|strongswan\|frr\|firewalld\|lxd\|incus or binary dockerd\|kubelet\|k3s\|wg\|openvpn\|libvirtd\|podman)) |
| `hardening:net.ipv4.tcp_max_syn_backlog` | Low | strict | Small TCP SYN backlog | always |
| `hardening:net.ipv4.tcp_rfc1337` | Low | strict | TIME-WAIT assassination protection disabled | always |
| `hardening:net.ipv4.tcp_syncookies` | Medium | basic | TCP SYN cookies disabled | always |
| `hardening:net.ipv6.conf.all.accept_ra` | Low | strict | IPv6 router advertisements accepted | always |
| `hardening:net.ipv6.conf.all.accept_redirects` | Medium | medium | IPv6 ICMP redirects accepted | always |
| `hardening:net.ipv6.conf.all.accept_source_route` | Medium | medium | IPv6 source routing accepted | always |
| `hardening:net.ipv6.conf.all.forwarding` | Low | strict | IPv6 forwarding enabled | not((package docker-ce\|docker.io\|moby-engine\|podman\|containerd.io\|kubelet\|k3s\|libvirt-daemon\|libvirt-daemon-system\|wireguard-tools\|openvpn\|strongswan\|frr\|lxd\|incus or binary dockerd\|kubelet\|k3s\|wg\|openvpn\|libvirtd\|podman)) |
| `hardening:net.ipv6.conf.default.accept_redirects` | Medium | medium | IPv6 ICMP redirects accepted on new interfaces | always |
| `hardening:net.ipv6.conf.default.accept_source_route` | Medium | medium | IPv6 source routing accepted on new interfaces | always |
| `hardening:vm.unprivileged_userfaultfd` | Low | strict | Unprivileged userfaultfd is allowed | always |

## InfluxDB 1.x and Apache Cassandra (`influxdb-cassandra`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `cassandra:authenticator-allowall` | High | medium | Cassandra authentication is disabled (AllowAllAuthenticator) | file /etc/influxdb/influxdb.conf\|/etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml; file /etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml |
| `cassandra:authorizer-allowall` | Medium | medium | Cassandra authorization is disabled (AllowAllAuthorizer) | file /etc/influxdb/influxdb.conf\|/etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml; file /etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml |
| `cassandra:client-encryption` | Low | strict | Cassandra client connections are not encrypted | file /etc/influxdb/influxdb.conf\|/etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml; file /etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml |
| `influxdb:auth-disabled` | High | medium | InfluxDB 1.x HTTP authentication is disabled | file /etc/influxdb/influxdb.conf\|/etc/cassandra/cassandra.yaml\|/etc/cassandra/conf/cassandra.yaml; file /etc/influxdb/influxdb.conf |

## Kubernetes node (kubelet and control-plane files) (`kubernetes`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `k8s:admin-kubeconfig-perms` | Critical | basic | Cluster-admin kubeconfig {path} is readable by other users | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:component-kubeconfig-perms` | Medium | medium | Component kubeconfig {path} is more permissive than 0600 | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:etcd-data-perms` | High | medium | etcd data directory is accessible to other users | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-anonymous-auth` | Critical | basic | kubelet accepts anonymous requests | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-authz-always-allow` | Critical | basic | kubelet authorization mode is AlwaysAllow | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-client-ca` | Medium | medium | kubelet has no client CA for certificate authentication | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-config-perms` | High | medium | kubelet config file is writable by non-root users | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-iptables-chains` | Low | strict | kubelet does not manage iptables utility chains | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-protect-kernel-defaults` | Low | strict | kubelet does not protect kernel defaults | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-read-only-port` | High | medium | kubelet read-only port is enabled | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-rotate-certificates` | Low | medium | kubelet client certificate rotation is off | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:kubelet-webhook-authn` | Medium | medium | kubelet webhook token authentication is disabled | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:manifest-perms` | Critical | medium | Static pod manifest {path} is writable by non-root users | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |
| `k8s:pki-key-perms` | High | medium | Kubernetes private key {path} is readable by other users | (file /var/lib/kubelet/config.yaml\|/etc/kubernetes or binary kubelet) |

## System logging (journald, rsyslog, /var/log) (`logging`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `log:audit-log-perms` | Medium | medium | Audit logs are accessible to other users | always |
| `log:btmp-readable` | Low | medium | Failed-login log (btmp) is readable by all users | always |
| `log:file-world-readable` | Low | strict | Log file readable by all users | always |
| `log:journald-compress` | Low | strict | journald compression disabled | file /etc/systemd/journald.conf\|/etc/systemd/journald.conf.d/*.conf |
| `log:journald-not-persistent` | Low | medium | journal is not persistent and no syslog daemon is installed | file /etc/systemd/journald.conf\|/usr/lib/systemd/systemd-journald\|/lib/systemd/systemd-journald; not(file /var/log/journal); not(package rsyslog\|syslog-ng\|syslog-ng-core) |
| `log:journald-volatile` | Low | medium | journald keeps logs only in memory (or not at all) | file /etc/systemd/journald.conf\|/etc/systemd/journald.conf.d/*.conf |
| `log:logrotate-missing` | Low | medium | rsyslog files are never rotated (logrotate.conf missing) | package rsyslog |
| `log:no-remote` | Low | strict | Logs are not forwarded to a remote host | package rsyslog |
| `log:rsyslog-filecreatemode` | Low | strict | rsyslog creates log files readable by everyone | package rsyslog |
| `log:rsyslog-not-running` | Low | medium | rsyslog is installed but not running | package rsyslog |
| `log:var-log-world-writable` | Medium | medium | World-writable file or directory under /var/log | always |

## Password aging and quality defaults (`login-defs`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `login-defs:encrypt-method` | High | medium | Weak password hashing configured in login.defs | always |
| `login-defs:home-mode` | Low | medium | New home directories are readable by other users | always |
| `login-defs:pass-max-days` | Medium | medium | Passwords never or rarely expire | always |
| `login-defs:pass-min-days` | Low | medium | Passwords can be changed again immediately | always |
| `login-defs:pass-warn-age` | Low | strict | Short password expiry warning | always |
| `login-defs:pw-dcredit` | Low | strict | Password policy doesn't require a digit | file /etc/security/pwquality.conf |
| `login-defs:pw-lcredit` | Low | strict | Password policy doesn't require a lowercase letter | file /etc/security/pwquality.conf |
| `login-defs:pw-minlen` | Medium | medium | Short minimum password length | file /etc/security/pwquality.conf |
| `login-defs:pw-ocredit` | Low | strict | Password policy doesn't require a special character | file /etc/security/pwquality.conf |
| `login-defs:pw-ucredit` | Low | strict | Password policy doesn't require an uppercase letter | file /etc/security/pwquality.conf |
| `login-defs:umask` | Low | strict | Default UMASK lets other users read new files | always |

## Mandatory access control (SELinux, AppArmor) (`mac`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `mac` | Medium | - | SELinux/AppArmor disabled or permissive | - |
| `mac:apparmor-complain-profiles` | Low | medium | AppArmor profiles in complain mode | binary aa-status; os debian\|ubuntu\|suse |
| `mac:apparmor-service-disabled` | Medium | medium | apparmor.service is not enabled at boot | unit apparmor.service; os debian\|ubuntu\|suse |
| `mac:apparmor-unconfined-with-profile` | Medium | medium | Processes run unconfined although an AppArmor profile exists | binary aa-status; os debian\|ubuntu\|suse |
| `mac:selinux-config-not-enforcing` | Medium | medium | SELinux is not set to enforcing in /etc/selinux/config | file /etc/selinux/config; os rhel\|fedora |
| `mac:selinux-httpd-execmem` | Low | medium | SELinux boolean httpd_execmem is on | package httpd\|nginx; os rhel\|fedora |
| `mac:selinux-httpd-unified` | Medium | medium | SELinux boolean httpd_unified is on | package httpd\|nginx; os rhel\|fedora |
| `mac:selinux-policy-not-targeted` | Low | medium | SELinux policy type is not targeted or mls | file /etc/selinux/config; os rhel\|fedora |
| `mac:selinux-troubleshoot-tools` | Low | strict | setroubleshoot or mcstrans is installed | os rhel\|fedora |

## Mail servers (Postfix, Exim, Dovecot) (`mail`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `dovecot:auth-mechanisms-cram` | Low | strict | Dovecot offers legacy challenge-response mechanisms | package dovecot\|dovecot-core |
| `dovecot:passwords-logged` | Medium | medium | Dovecot logs passwords | package dovecot\|dovecot-core |
| `dovecot:plaintext-auth` | High | medium | Dovecot allows plaintext authentication without TLS | package dovecot\|dovecot-core |
| `dovecot:ssl-disabled` | High | medium | Dovecot TLS is disabled | package dovecot\|dovecot-core |
| `dovecot:weak-ssl-protocol` | Medium | medium | Dovecot accepts SSLv3/TLS 1.0/TLS 1.1 | package dovecot\|dovecot-core |
| `exim:dc-relay-nets-open` | Critical | basic | Exim (Debian) relays for any network | package exim4\|exim4-daemon-light\|exim4-daemon-heavy |
| `exim:relay-from-hosts-open` | Critical | basic | Exim relay_from_hosts allows any host | package exim\|exim4\|exim4-daemon-light\|exim4-daemon-heavy |
| `postfix:auth-without-tls` | Medium | medium | Postfix allows SMTP AUTH over unencrypted connections | package postfix |
| `postfix:banner-version` | Low | medium | Postfix SMTP banner discloses the version | package postfix |
| `postfix:mynetworks-open` | Critical | basic | Postfix mynetworks trusts the whole internet (open relay) | package postfix |
| `postfix:no-tls` | Medium | medium | Postfix accepts SMTP without offering TLS | package postfix; port 25 |
| `postfix:not-local-only` | Low | strict | Postfix listens on all interfaces | package postfix |
| `postfix:relay-unrestricted` | Critical | basic | Postfix relay restrictions lack reject_unauth_destination | package postfix |
| `postfix:sasl-passwd-perms` | High | medium | Postfix relay credentials are readable by other users | package postfix |
| `postfix:vrfy-enabled` | Low | medium | Postfix answers VRFY (user enumeration) | package postfix |
| `postfix:weak-tls-protocols` | Medium | medium | Postfix explicitly enables SSLv2/SSLv3 | package postfix |

## Memcached (`memcached`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `memcached:listen-not-local` | Medium | medium | Memcached is not restricted to loopback | file /etc/memcached.conf\|/etc/sysconfig/memcached |
| `memcached:udp-enabled` | High | medium | Memcached UDP listener is enabled | file /etc/memcached.conf\|/etc/sysconfig/memcached |

## Unneeded kernel modules (`modules`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `module:bluetooth` | Low | strict | Bluetooth stack can be loaded on a server | always |
| `module:cramfs` | Low | medium | cramfs filesystem module can be loaded | always |
| `module:dccp` | Medium | medium | DCCP protocol module can be loaded | always |
| `module:firewire-core` | Low | strict | FireWire module can be loaded | always |
| `module:freevxfs` | Low | medium | freevxfs filesystem module can be loaded | always |
| `module:hfs` | Low | medium | hfs filesystem module can be loaded | always |
| `module:hfsplus` | Low | medium | hfsplus filesystem module can be loaded | always |
| `module:jffs2` | Low | medium | jffs2 filesystem module can be loaded | always |
| `module:n_hdlc` | Low | strict | n_hdlc line discipline module can be loaded | always |
| `module:rds` | Medium | medium | RDS protocol module can be loaded | always |
| `module:sctp` | Low | medium | SCTP protocol module can be loaded | always |
| `module:squashfs` | Low | strict | squashfs filesystem module can be loaded | not(package snapd) |
| `module:tipc` | Medium | medium | TIPC protocol module can be loaded | always |
| `module:udf` | Low | strict | udf filesystem module can be loaded | always |
| `module:usb-storage` | Low | medium | USB mass storage can be used | always |

## MongoDB (`mongodb`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `mongodb:authorization-disabled` | High | basic | MongoDB access control is not enabled | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:bind-all` | Medium | medium | MongoDB is configured to listen on all interfaces | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:config-writable` | High | medium | mongod.conf is writable by other users | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:eol` | High | medium | MongoDB server version is end-of-life | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:javascript-enabled` | Low | strict | Server-side JavaScript is enabled | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:process-root` | Medium | medium | mongod runs as root | file /etc/mongod.conf\|/usr/bin/mongod |
| `mongodb:tls-disabled-remote` | Medium | medium | MongoDB accepts remote connections without TLS | file /etc/mongod.conf\|/usr/bin/mongod |

## Monitoring agents and dashboards (Zabbix, Prometheus, node_exporter, Grafana, Netdata) (`monitoring`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `grafana:allow-sign-up` | Medium | medium | Grafana allows users to sign up | file /etc/grafana/grafana.ini |
| `grafana:anonymous-access` | Medium | medium | Grafana anonymous access is enabled | file /etc/grafana/grafana.ini |
| `grafana:config-readable` | Medium | medium | grafana.ini is readable by other users | file /etc/grafana/grafana.ini |
| `grafana:cookie-secure` | Low | strict | Grafana session cookies are not marked Secure | file /etc/grafana/grafana.ini |
| `netdata:exposed` | Medium | medium | Netdata agent is reachable on a network address | (binary netdata or file /etc/netdata/netdata.conf) |
| `node-exporter:exposed` | Low | medium | node_exporter is reachable on a network address | binary node_exporter\|prometheus-node-exporter |
| `prometheus:admin-api` | Medium | medium | Prometheus admin API is enabled | binary prometheus |
| `prometheus:exposed` | Medium | medium | Prometheus server is reachable on a network address | binary prometheus |
| `prometheus:lifecycle-api` | Low | medium | Prometheus lifecycle API is enabled | binary prometheus |
| `zabbix:agent-allow-root` | High | medium | Zabbix agent runs as root (AllowRoot=1) | file /etc/zabbix/zabbix_agentd.conf |
| `zabbix:agent-allow-system-run` | High | medium | Zabbix agent allows system.run | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |
| `zabbix:agent-config-writable` | High | medium | Zabbix agent configuration {path} is writable by non-root users | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |
| `zabbix:agent-remote-commands` | High | medium | Zabbix agent remote commands are enabled | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |
| `zabbix:agent-server-any` | High | medium | Zabbix agent accepts passive checks from any address | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |
| `zabbix:agent-unencrypted` | Low | strict | Zabbix agent accepts unencrypted connections | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |
| `zabbix:frontend-config-readable` | Medium | medium | Zabbix frontend config {path} is readable by other users | file /etc/zabbix/web/zabbix.conf.php\|/usr/share/zabbix/conf/zabbix.conf.php |
| `zabbix:server-config-readable` | High | medium | Zabbix server/proxy config {path} is readable by other users | file /etc/zabbix/zabbix_server.conf\|/etc/zabbix/zabbix_proxy.conf |
| `zabbix:unsafe-user-parameters` | Medium | medium | Zabbix agent allows unsafe UserParameter arguments | file /etc/zabbix/zabbix_agentd.conf\|/etc/zabbix/zabbix_agent2.conf |

## Mount options for temporary and data filesystems (`mount`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `mount:dev-shm:nodev` | Medium | medium | /dev/shm mounted without nodev | always |
| `mount:dev-shm:noexec` | Medium | medium | /dev/shm mounted without noexec | always |
| `mount:dev-shm:nosuid` | Medium | medium | /dev/shm mounted without nosuid | always |
| `mount:home:nodev` | Low | strict | /home mounted without nodev | always |
| `mount:home:nosuid` | Low | strict | /home mounted without nosuid | always |
| `mount:proc:hidepid` | Low | strict | Process list visible to all users | always |
| `mount:tmp:nodev` | Medium | medium | /tmp mounted without nodev | always |
| `mount:tmp:noexec` | Medium | medium | /tmp mounted without noexec | always |
| `mount:tmp:nosuid` | Medium | medium | /tmp mounted without nosuid | always |
| `mount:tmp:separate` | Low | strict | /tmp is not a separate filesystem | always |
| `mount:var-log:noexec` | Low | strict | /var/log mounted without nodev, nosuid or noexec | always |
| `mount:var-tmp:nodev` | Medium | medium | /var/tmp mounted without nodev | always |
| `mount:var-tmp:noexec` | Medium | medium | /var/tmp mounted without noexec | always |
| `mount:var-tmp:nosuid` | Medium | medium | /var/tmp mounted without nosuid | always |
| `mount:var:nodev` | Low | strict | /var mounted without nodev | always |

## MySQL / MariaDB server (`mysql`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `mariadb:eol-upstream` | High | medium | Upstream MariaDB server version is end-of-life | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe; package MariaDB-server |
| `mariadb:local-infile-default` | Low | strict | MariaDB allows LOAD DATA LOCAL INFILE by default | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe; package mariadb-server\|MariaDB-server |
| `mariadb:secure-file-priv-unset` | Low | strict | MariaDB does not restrict FILE import/export (secure_file_priv unset) | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe; package mariadb-server\|MariaDB-server |
| `mysql:allow-suspicious-udfs` | Medium | medium | allow-suspicious-udfs is enabled | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:bind-all-interfaces` | Medium | medium | MySQL is configured to listen on all interfaces | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:config-user-root` | High | medium | MySQL is configured to run as root | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:config-writable` | High | medium | MySQL configuration file is writable by non-root users | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:datadir-world-readable` | Low | strict | MySQL data directory is accessible to all users | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:datadir-world-writable` | High | medium | MySQL data directory is world-writable | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:debian-cnf-perms` | High | medium | /etc/mysql/debian.cnf is readable by non-root users | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:eol-community` | High | medium | Oracle MySQL Community Server version is end-of-life | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe; package mysql-community-server |
| `mysql:general-log` | Low | medium | General query log is enabled | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:history-file` | Low | strict | MySQL client history file is kept | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:local-infile` | Medium | medium | LOAD DATA LOCAL INFILE is enabled | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:log-raw` | Medium | medium | log-raw writes passwords to the logs | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:native-password-default` | Low | strict | Default authentication plugin is mysql_native_password | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:old-passwords` | High | medium | Pre-4.1 password hashing is enabled (old_passwords) | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:process-root` | High | medium | MySQL server process runs as root | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:require-secure-transport` | Low | strict | Remote clients may connect without TLS | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:secure-file-priv-empty` | Medium | medium | secure_file_priv is explicitly empty | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:skip-grant-tables` | Critical | basic | MySQL starts with skip-grant-tables (no authentication) | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:skip-ssl` | Medium | medium | TLS is disabled for client connections | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:symbolic-links` | Low | strict | Symbolic links to tables are enabled | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:tls-legacy-versions` | Medium | medium | Server allows TLS 1.0/1.1 | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |
| `mysql:user-mycnf-readable` | High | medium | A user's ~/.my.cnf (client credentials) is readable by others | file /usr/sbin/mysqld\|/usr/sbin/mariadbd\|/usr/libexec/mysqld\|/usr/libexec/mariadbd\|/usr/bin/mysqld_safe |

## Go rule (`network`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `net:exposed` | Medium | - | TCP service listening on all interfaces (other than 22/80/443) | - |

## nginx web server (`nginx`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `nginx:access-log-off` | Low | medium | nginx access logging disabled globally | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:alias-dangerous` | Critical | basic | nginx alias exposes a system directory | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:alias-traversal` | High | medium | nginx alias path traversal (location without trailing slash) | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:client-max-body-unlimited` | Low | medium | nginx accepts request bodies of unlimited size | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:conf-not-root-owned` | Medium | medium | nginx configuration owned by a non-root user | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:conf-world-writable` | High | medium | nginx configuration writable by any user | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:csp-missing` | Low | strict | nginx sends no Content-Security-Policy header | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:error-log-debug` | Low | strict | nginx error log at debug level | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:htpasswd-weak-hash` | Medium | medium | nginx basic-auth file uses weak or plain-text password hashes | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:htpasswd-world-readable` | Medium | medium | nginx basic-auth password file readable by any user | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:log-world-readable` | Low | strict | nginx log files readable by any user | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:merge-slashes-off` | Medium | medium | nginx merge_slashes is off | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:referrer-policy-missing` | Low | strict | nginx sends no Referrer-Policy header | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:root-dangerous` | Critical | basic | nginx serves a system directory as document root | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:ssi-on` | Low | medium | nginx server-side includes enabled | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |
| `nginx:user-root` | High | basic | nginx worker processes run as root | (package nginx\|nginx-core\|nginx-full\|nginx-light\|nginx-extras\|nginx-mainline\|openresty or file /etc/nginx/nginx.conf) |

## PAM authentication stack (`pam`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `pam:faillock-deny` | Low | medium | faillock allows too many failed attempts (or none) | file /etc/pam.d; file /etc/security/faillock.conf |
| `pam:faillock-unlock-time` | Low | strict | faillock unlocks accounts too quickly | file /etc/pam.d; file /etc/security/faillock.conf |
| `pam:minclass` | Low | strict | Password complexity does not require several character classes | file /etc/pam.d; file /etc/security/pwquality.conf |
| `pam:no-lockout` | Medium | medium | No failed-login lockout (pam_faillock/pam_tally2) in the auth stack | file /etc/pam.d |
| `pam:no-pwquality` | Low | medium | No password-quality module in the password stack | file /etc/pam.d |
| `pam:nullok` | Low | medium | pam_unix accepts empty passwords (nullok) | file /etc/pam.d |
| `pam:permit-auth` | Critical | basic | PAM auth stack accepts any password (pam_permit is sufficient) | file /etc/pam.d |
| `pam:pwhistory` | Low | strict | Password reuse is not restricted | file /etc/pam.d |
| `pam:rhosts` | High | medium | pam_rhosts trusts .rhosts host equivalence | file /etc/pam.d |
| `pam:su-wheel` | Low | medium | su is not restricted to the wheel/sudo group | file /etc/pam.d; file /etc/pam.d/su |
| `pam:weak-hash` | Medium | medium | pam_unix hashes new passwords with a weak algorithm | file /etc/pam.d |

## PHP runtime configuration (php.ini) (`php`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `php:allow-url-fopen` | Low | strict | PHP can open remote URLs as files (allow_url_fopen on) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:allow-url-include` | High | - | allow_url_include=On enables remote file inclusion | - |
| `php:auto-append-tmp` | High | medium | PHP auto_append_file points into a world-writable temp directory | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:auto-prepend-tmp` | High | medium | PHP auto_prepend_file points into a world-writable temp directory | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:cgi-fix-pathinfo` | Low | - | cgi.fix_pathinfo=1 (default) with FPM | - |
| `php:disable-functions-empty` | Low | - | disable_functions is empty (no defense in depth against webshells) | - |
| `php:display-errors` | Medium | - | display_errors on: errors (paths, SQL) shown to visitors | - |
| `php:display-startup-errors` | Low | medium | PHP displays startup errors (display_startup_errors on) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:eol-branch` | High | - | PHP branch past upstream end-of-life (<= 8.1) | - |
| `php:exception-ignore-args` | Low | strict | PHP stack traces include function arguments | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:expose-php` | Low | - | expose_php=On advertises the PHP version | - |
| `php:ffi-enabled` | Medium | medium | PHP FFI enabled for all scripts | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:log-errors-off` | Low | medium | PHP does not log errors (log_errors off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:mail-add-x-header` | Low | strict | PHP mail() adds X-PHP-Originating-Script headers | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:memory-limit-unlimited` | Low | medium | PHP memory_limit is unlimited | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:open-basedir-unset` | Low | strict | PHP file access not confined (open_basedir unset) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:phar-readonly-off` | Low | medium | PHP scripts can create PHAR archives (phar.readonly off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:register-argc-argv` | Low | medium | PHP registers $argc/$argv for web requests (register_argc_argv on) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-cookie-httponly` | Medium | medium | PHP session cookie readable by JavaScript (session.cookie_httponly off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-cookie-samesite` | Low | strict | PHP session cookie has no SameSite attribute | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-cookie-secure` | Low | strict | PHP session cookie sent over plain HTTP (session.cookie_secure off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-path` | Medium | - | session.save_path missing or not writable by the pool user | - |
| `php:session-use-cookies` | Medium | medium | PHP sessions do not use cookies (session.use_cookies off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-use-only-cookies` | Medium | medium | PHP accepts session IDs from URLs (session.use_only_cookies off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-use-strict-mode` | Medium | medium | PHP accepts uninitialised session IDs (session.use_strict_mode off) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:session-use-trans-sid` | Medium | medium | PHP rewrites URLs to carry the session ID (session.use_trans_sid on) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:upload-progress` | High | - | session.upload_progress.enabled is On (default) - exposure for CVE-2026-109618 / CVE-2026-109619 | - |
| `php:user-ini-enabled` | Low | strict | PHP honours per-directory .user.ini files | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:xdebug-discover-client-host` | High | medium | Xdebug connects back to any client (xdebug.discover_client_host) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:xdebug-loaded` | Medium | medium | Xdebug extension loaded in a server PHP installation | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:xdebug-remote-connect-back` | High | medium | Xdebug 2 connects back to any client (xdebug.remote_connect_back) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |
| `php:zend-assertions` | Low | strict | PHP assertions are compiled and executed (zend.assertions not -1) | file /etc/php.ini\|/etc/php/*/*/php.ini\|/etc/opt/remi/php*/php.ini\|/etc/php*/php.ini |

## PHP-FPM pools (`php-fpm`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `php-fpm:clear-env-off` | Low | medium | PHP-FPM passes the master's environment to scripts (clear_env = no) | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:conf-world-writable` | High | medium | PHP-FPM configuration writable by any user | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:limit-extensions` | High | medium | PHP-FPM executes non-.php files as PHP | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:listen-exposed` | Critical | basic | PHP-FPM FastCGI port reachable from the network | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:listen-mode` | High | medium | PHP-FPM socket permissions allow any local user | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:pool-group-root` | Medium | medium | PHP-FPM pool runs with group root | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:pool-root` | Critical | basic | PHP-FPM pool runs as root | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:pool-web-server-user` | Low | strict | PHP-FPM pool runs as the web server user | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:socket-world-writable` | High | medium | PHP-FPM socket writable by any local user | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |
| `php-fpm:status-path` | Low | strict | PHP-FPM status page enabled | file /etc/php-fpm.d\|/etc/php-fpm.conf\|/etc/php/*/fpm\|/etc/opt/remi/php*/php-fpm.d\|/etc/php*/php-fpm.d |

## PostgreSQL server (`postgresql`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `postgres:config-writable` | High | medium | PostgreSQL configuration is writable by other users | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:eol-pgdg` | High | medium | PostgreSQL (PGDG build) major version is end-of-life | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-ident-remote` | High | medium | pg_hba.conf trusts remote ident servers | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-md5` | Low | strict | pg_hba.conf uses md5 authentication | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-open-to-any` | Medium | medium | pg_hba.conf allows logins from any address | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-password-cleartext` | High | medium | pg_hba.conf uses cleartext password authentication over TCP | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-trust-local` | High | medium | pg_hba.conf trusts local connections without a password | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:hba-trust-remote` | Critical | basic | pg_hba.conf trusts network clients without a password | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:listen-all` | Medium | medium | PostgreSQL is configured to listen on all interfaces | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:log-connections` | Low | strict | Connections are not logged | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:log-disconnections` | Low | strict | Session ends are not logged | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:password-encryption-md5` | Medium | medium | New passwords are stored as MD5 | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:pgpass-perms` | High | medium | A .pgpass password file is readable by other users | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:ssl-min-protocol` | Medium | medium | PostgreSQL allows TLS 1.0/1.1 | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |
| `postgres:ssl-off-remote` | Medium | medium | PostgreSQL accepts remote connections without TLS | file /etc/postgresql/*/main/postgresql.conf\|/var/lib/pgsql/data/postgresql.conf\|/var/lib/pgsql/*/data/postgresql.conf |

## RabbitMQ (`rabbitmq`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `rabbitmq:config-readable-secret` | High | medium | RabbitMQ config with passwords is readable by all users | file /etc/rabbitmq/rabbitmq.conf\|/etc/rabbitmq/rabbitmq.config\|/usr/sbin/rabbitmq-server\|/usr/lib/rabbitmq/bin/rabbitmq-server |
| `rabbitmq:config-writable` | High | medium | RabbitMQ configuration is writable by other users | file /etc/rabbitmq/rabbitmq.conf\|/etc/rabbitmq/rabbitmq.config\|/usr/sbin/rabbitmq-server\|/usr/lib/rabbitmq/bin/rabbitmq-server |
| `rabbitmq:erlang-cookie-perms` | High | medium | Erlang cookie is readable by other users | file /etc/rabbitmq/rabbitmq.conf\|/etc/rabbitmq/rabbitmq.config\|/usr/sbin/rabbitmq-server\|/usr/lib/rabbitmq/bin/rabbitmq-server |
| `rabbitmq:guest-remote` | High | medium | RabbitMQ guest account may log in remotely | file /etc/rabbitmq/rabbitmq.conf\|/etc/rabbitmq/rabbitmq.config\|/usr/sbin/rabbitmq-server\|/usr/lib/rabbitmq/bin/rabbitmq-server |
| `rabbitmq:tls-legacy` | Medium | medium | RabbitMQ allows TLS 1.0/1.1 | file /etc/rabbitmq/rabbitmq.conf\|/etc/rabbitmq/rabbitmq.config\|/usr/sbin/rabbitmq-server\|/usr/lib/rabbitmq/bin/rabbitmq-server |

## Redis / Valkey (`redis`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `redis:bind-all` | Medium | medium | Redis is configured to listen on all interfaces | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:config-command` | Low | strict | Redis CONFIG command is not renamed or disabled | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:config-readable-secret` | High | medium | Redis config with a password is readable by all users | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:config-writable` | High | medium | Redis configuration is writable by other users | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:debug-command` | Medium | medium | Redis DEBUG command is enabled for remote clients | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:module-command` | High | medium | Redis MODULE command is enabled for remote clients | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:process-root` | High | medium | Redis server runs as root | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:protected-configs` | Medium | medium | Redis protected configs can be changed at runtime | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:protected-mode-off` | High | medium | Redis protected mode is disabled on an instance without a password | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |
| `redis:unixsocket-perm` | Medium | medium | Redis Unix socket is world-writable | file /etc/redis.conf\|/etc/redis/redis.conf\|/etc/redis/redis-*.conf\|/etc/valkey/valkey.conf |

## Remote administration (Webmin, Cockpit, VNC, xrdp, X11) (`remote-admin`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `cockpit:allow-unencrypted` | High | medium | Cockpit allows unencrypted HTTP logins | package cockpit\|cockpit-ws |
| `cockpit:root-login-allowed` | Medium | medium | Cockpit allows root to log in | package cockpit\|cockpit-ws |
| `vnc:no-auth` | Critical | medium | VNC server configured without authentication | (package tigervnc-server\|tigervnc-standalone-server or file /etc/tigervnc) |
| `vnc:passwd-perms` | Medium | medium | VNC password file is readable by other users | file /root/.vnc/passwd\|/home/*/.vnc/passwd\|/home/*/.config/tigervnc/passwd |
| `vnc:public-listener` | High | medium | VNC server reachable on a public interface | port 5900\|5901\|5902\|5903\|5904\|5905\|5906\|5907\|5908\|5909\|5910 |
| `webmin:no-ip-allowlist` | Low | medium | Webmin accepts connections from any address | (package webmin or file /etc/webmin/miniserv.conf) |
| `webmin:public-listener` | High | medium | Webmin is reachable on a public interface | (package webmin or file /etc/webmin/miniserv.conf) |
| `webmin:ssl-off` | High | medium | Webmin serves logins over plain HTTP | (package webmin or file /etc/webmin/miniserv.conf) |
| `webmin:users-file-perms` | High | medium | Webmin user/password file is readable by other users | (package webmin or file /etc/webmin/miniserv.conf) |
| `x11:tcp-listener` | High | medium | X server accepts TCP connections from the network | port 6000\|6001\|6002\|6003\|6004\|6005\|6006\|6007\|6008\|6009\|6010 |
| `xrdp:low-crypt-level` | Medium | medium | xrdp uses low or no RDP encryption | package xrdp |
| `xrdp:rdp-security-layer` | High | medium | xrdp uses the legacy RDP security layer (no TLS) | package xrdp |
| `xrdp:root-login` | Medium | medium | xrdp allows root desktop logins | package xrdp |

## Application runtimes (Node.js/PM2, Python WSGI servers, Java) (`runtimes`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `container:eol-base` | Medium | - | Image tag names an EOL runtime (postgres<=13, node<=20, php<=8.1, python<=3.9, mysql 5.x, redis<=6) | - |
| `container:image-age` | Medium | - | Running container image built longer ago than rules.image_max_age_days (default 365) | - |
| `container:latest-tag` | Low | - | Container runs an image referenced by :latest (or no tag): unpinned, unknown patch level | - |
| `container:php-upload-progress` | High | - | PHP inside running containers has session.upload_progress.enabled on (docker exec; opt-in) **(opt-in)** | - |
| `container:restart-loop` | Low | - | Container with restart policy always/unless-stopped that is exited or restarting repeatedly | - |
| `gunicorn:bind-public` | Low | medium | gunicorn bound to all interfaces in a systemd unit | binary gunicorn |
| `java:jdwp-exposed` | Critical | basic | Java debug agent (JDWP) listening on all interfaces | (binary java or file /usr/lib/jvm\|/opt/java) |
| `java:jmx-no-auth` | High | medium | Java JMX remote access enabled without authentication | (binary java or file /usr/lib/jvm\|/opt/java) |
| `node:inspector-exposed` | Critical | basic | Node.js inspector listening on a network address | binary node\|nodejs |
| `node:process-root` | Low | medium | Node.js process runs as root | binary node\|nodejs |
| `pm2:daemon-root` | Medium | medium | PM2 runs as root | (binary pm2 or file /usr/lib/node_modules/pm2\|/usr/local/lib/node_modules/pm2\|/etc/systemd/system/pm2-root.service) |
| `runtime:eol-node` | High | - | Running node process uses an end-of-life Node.js major (incl. nvm installs) | - |
| `runtime:eol-python` | Medium | - | Running python process uses an end-of-life CPython outside distro paths (pyenv, /usr/local, conda) | - |
| `upstream:node-cve` | Critical | - | Non-distro Node.js is inside a vulnerable range of a Node.js core CVE (nodejs/security-wg vuln/core, CVSS from NVD) | - |
| `upstream:node-security-release` | High | - | Non-distro Node.js (nvm, fnm, volta, asdf, n, tarball, NodeSource, node: image) is older than a security release on its major line (nodejs.org/dist/index.json) | - |
| `uwsgi:http-public` | Low | medium | uWSGI HTTP router listening on all interfaces ({_key}) | (binary uwsgi or package uwsgi\|uwsgi-core) |
| `uwsgi:uid-root` | Medium | medium | uWSGI app {_key} is configured to run as root | (binary uwsgi or package uwsgi\|uwsgi-core) |
| `uwsgi:vassal-world-writable` | High | medium | uWSGI vassal config {path} is world-writable | (binary uwsgi or package uwsgi\|uwsgi-core) |

## Secrets hygiene (keys, credential files, shell history) (`secrets`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `secrets:credential-file-readable` | High | medium | Credential file {path} is readable by other users | always |
| `secrets:docker-config-readable` | Medium | medium | Docker client config {path} is readable by other users | always |
| `secrets:gnupg-dir-perms` | Low | strict | GnuPG home {path} is accessible to other users | always |
| `secrets:kubeconfig-readable` | High | medium | kubeconfig {path} is readable by other users | always |
| `secrets:shell-history-credentials` | Medium | medium | Shell history {path} contains credentials | always |
| `secrets:shell-history-readable` | Low | medium | Shell history {path} is readable by other users | always |
| `secrets:ssh-private-key-readable` | High | medium | SSH private key {path} is readable by other users | always |
| `secrets:temp-private-key` | Medium | medium | Readable private key material in a temporary directory ({path}) | always |
| `secrets:tls-private-key-readable` | High | medium | TLS private key {path} is readable by other users | always |

## Legacy and unneeded network services (`services-legacy`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `svc:avahi` | Low | strict | Avahi (mDNS/DNS-SD) daemon running | always |
| `svc:cups` | Low | strict | CUPS print service running | always |
| `svc:dhcp-server` | Low | strict | DHCP server installed | always |
| `svc:finger-server` | Low | medium | finger server installed | always |
| `svc:inetd` | Low | medium | inetd/xinetd super-server installed | always |
| `svc:nis-client` | Low | strict | NIS client installed | always |
| `svc:nis-server` | Medium | medium | NIS server (ypserv) installed | always |
| `svc:prelink` | Low | strict | prelink installed | always |
| `svc:rpcbind-unused` | Low | medium | rpcbind running without NFS or NIS | not(package nfs-utils\|nfs-kernel-server\|nfs-common\|ypbind\|ypserv\|nis\|glusterfs-server) |
| `svc:rsh-client` | Low | strict | rsh client installed | always |
| `svc:rsh-listening` | High | basic | rexec/rlogin server listening (512/513 tcp) | always |
| `svc:rsh-server` | High | medium | rsh/rlogin/rexec server package installed | always |
| `svc:small-services` | Medium | medium | echo/discard/daytime/chargen/time service listening | always |
| `svc:talk-server` | Low | medium | talk server installed | always |
| `svc:telnet-client` | Low | strict | telnet client installed | always |
| `svc:telnet-listening` | High | basic | Telnet server listening | always |
| `svc:telnet-server` | Medium | medium | Telnet server package installed | always |
| `svc:tftp-server` | Medium | medium | TFTP server installed | always |
| `svc:x-server` | Info | strict | X Window server installed on a server | always |

## SNMP agent (net-snmp) (`snmp`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `snmp:community-any-source` | Medium | medium | SNMP community accepted from any address | package net-snmp\|snmpd |
| `snmp:config-readable` | Medium | medium | snmpd.conf is readable by other users | package net-snmp\|snmpd |
| `snmp:default-community` | Medium | basic | SNMP uses a default community string (public/private) | package net-snmp\|snmpd |
| `snmp:public-listener` | Low | medium | snmpd listens on a non-loopback address | package net-snmp\|snmpd |
| `snmp:write-community` | High | medium | SNMP grants write access with a community string | package net-snmp\|snmpd |

## OpenSSH server (`ssh`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `ssh:access-restriction` | Low | strict | SSH login not restricted to named users or groups | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:agent-forwarding` | Low | strict | SSH agent forwarding allowed | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:authorized-key-dsa` | Medium | medium | authorized_keys accepts a DSA key | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:client-alive-interval` | Low | medium | Idle SSH sessions never time out | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:config-perms` | Critical | basic | sshd configuration writable by non-root users | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:dsa-host-key` | Medium | medium | sshd uses a DSA host key | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:empty-passwords` | Critical | basic | SSH accepts empty passwords | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:gateway-ports` | Medium | medium | SSH remote forwards bind to all interfaces | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:gssapi-auth` | Low | strict | SSH GSSAPI authentication enabled | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:host-based-auth` | High | basic | SSH host-based authentication enabled | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:host-key-perms` | High | basic | SSH private host key readable by other users | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:ignore-rhosts` | High | basic | SSH honours .rhosts files | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:kbd-interactive-password` | Medium | medium | Passwords still accepted through keyboard-interactive auth | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:kerberos-auth` | Low | strict | SSH Kerberos password authentication enabled | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:log-level` | Low | medium | SSH logging below INFO | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:login-grace-time` | Low | medium | SSH LoginGraceTime is long | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:max-auth-tries` | Medium | medium | SSH MaxAuthTries is permissive | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:max-sessions` | Low | strict | SSH MaxSessions is high | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:max-startups` | Low | strict | SSH MaxStartups disabled or very high | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:no-banner` | Low | strict | SSH shows no warning banner | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:password-auth` | Medium | medium | SSH accepts password authentication | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:permit-root-login` | High | basic | SSH allows direct root login | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:permit-tunnel` | Low | strict | SSH tun/tap tunnelling allowed | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:permit-user-environment` | Medium | medium | Users can set environment variables for sshd sessions | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:protocol-1` | Critical | basic | SSH protocol 1 enabled | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:root-password-login` | Critical | basic | Root can log in over SSH with a password | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:strict-modes` | Medium | medium | sshd does not check home and key file permissions | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:tcp-forwarding` | Low | strict | SSH TCP forwarding allowed | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:weak-cipher` | Medium | medium | SSH offers weak cipher {value} | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:weak-kex` | Medium | medium | SSH offers weak key exchange {value} | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:weak-mac` | Medium | medium | SSH offers weak MAC {value} | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:x11-forwarding` | Low | medium | SSH X11 forwarding enabled | (file /etc/ssh/sshd_config or binary sshd) |
| `ssh:x11-use-localhost` | Medium | medium | Forwarded X11 display listens on all interfaces | (file /etc/ssh/sshd_config or binary sshd) |

## sudo policy (/etc/sudoers and sudoers.d) (`sudo`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `sudo:all-users` | Critical | basic | sudoers grants root to every user (ALL as the user list) | file /etc/sudoers |
| `sudo:env-keep-dangerous` | High | medium | sudo preserves a code-loading environment variable (env_keep) | file /etc/sudoers |
| `sudo:no-authenticate` | High | medium | sudo never asks for a password (Defaults !authenticate) | file /etc/sudoers |
| `sudo:no-env-reset` | High | medium | sudo keeps the caller's environment (Defaults !env_reset) | file /etc/sudoers |
| `sudo:no-logfile` | Low | strict | sudo has no dedicated log file | file /etc/sudoers |
| `sudo:shell-escape` | Medium | medium | sudo rule grants a command that can spawn a root shell | file /etc/sudoers |
| `sudo:stale-entry` | Low | medium | Stale sudoers entry for a user that doesn't exist: {principal} | file /etc/sudoers; not(package sssd\|sssd-common\|sssd-ldap\|nslcd\|libnss-ldapd\|nss-pam-ldapd\|winbind\|freeipa-client\|ipa-client) |
| `sudo:stale-group` | Low | medium | Stale sudoers entry for a group that doesn't exist: {principal} | file /etc/sudoers; not(package sssd\|sssd-common\|sssd-ldap\|nslcd\|libnss-ldapd\|nss-pam-ldapd\|winbind\|freeipa-client\|ipa-client) |
| `sudo:sudoers-d-perms` | Medium | medium | sudoers.d drop-in has unsafe ownership or permissions | file /etc/sudoers |
| `sudo:sudoers-perms` | Medium | medium | /etc/sudoers has unsafe ownership or permissions | file /etc/sudoers |
| `sudo:timestamp-timeout` | Low | medium | sudo credential cache lasts too long | file /etc/sudoers |
| `sudo:use-pty` | Low | strict | sudo does not run commands in a pseudo-terminal (use_pty) | file /etc/sudoers |
| `sudo:visiblepw` | Medium | medium | sudo may read passwords with echo on (Defaults visiblepw) | file /etc/sudoers |
| `sudo:wildcard-args` | Low | medium | sudo rule uses a wildcard in command arguments | file /etc/sudoers |

## SUID/SGID binaries and writable system paths (`suid`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `suid:dangerous-binary` | Critical | basic | Shell, interpreter or file tool {path} is setuid | always |
| `suid:path-dir-writable` | Critical | basic | Directory in root's PATH is writable by non-root users ({path}) | always |
| `suid:system-binary-world-writable` | Critical | medium | World-writable program in a system bin directory ({path}) | always |
| `suid:tmp-sticky` | High | basic | Shared temp directory {path} lacks the sticky bit | always |
| `suid:unusual-location` | High | medium | Set-id program in a user-writable location ({path}) | always |

## Go rule (`system`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `mac:selinux-runtime-drift` | High | - | SELinux enforcing in /etc/selinux/config but permissive/disabled at runtime (setenforce 0) | - |
| `sys:boot-kernel-downgrade` | High | - | Boot default kernel is older than the running kernel: next reboot silently downgrades | - |
| `sys:kernel-repo` | Medium | - | Running kernel package comes from a disabled or unknown repo (e.g. elrepo kernel-ml with the repo off): no updates | - |
| `sys:reboot-required` | Medium | - | Running kernel is older than the newest installed kernel (patches not active until reboot) | - |
| `sys:uptime` | Low | - | Uptime over 180 days | - |
| `systemd:failed-unit` | Medium | - | systemd units in failed state (enabled ones rate higher) | - |
| `updates:no-auto` | Medium | - | No automatic security updates (dnf-automatic / unattended-upgrades absent or disabled) | - |
| `updates:pending-security` | High | - | Pending security advisories (dnf updateinfo, cache only), by severity with the oldest advisory | - |

## Time synchronisation (chrony, ntpd, systemd-timesyncd) (`time`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `time:chrony-cmdport-exposed` | Low | medium | chronyc command port (323/udp) listens on the network | package chrony |
| `time:chrony-no-sources` | Low | medium | chrony has no time sources configured | package chrony |
| `time:chronyd-root` | Low | medium | chronyd runs as root | always |
| `time:no-sync` | Medium | medium | No time synchronisation service is running | binary systemctl |
| `time:ntp-restrict-default` | Medium | medium | ntpd answers status queries from any host (no 'restrict default ... noquery') | package ntp\|ntpsec |
| `time:ntpd-root` | Low | medium | ntpd runs as root | always |

## TLS certificates and private keys (`tls`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `tls:expired` | High | medium | TLS certificate expired: {path} | always |
| `tls:expiring-soon` | Medium | medium | TLS certificate expires within 21 days: {path} | always |
| `tls:key-not-root-owned` | Low | strict | TLS private key not owned by root: {path} | always |
| `tls:key-world-readable` | High | basic | TLS private key readable by any user: {path} | always |
| `tls:key-writable` | High | medium | TLS private key writable by group or others: {path} | always |
| `tls:letsencrypt-dir-perms` | High | medium | Let's Encrypt key directory accessible to other users: {path} | always |
| `tls:self-signed` | Low | strict | Web server uses a self-signed certificate: {path} | always |
| `tls:weak-rsa-key` | High | medium | TLS certificate uses an RSA key shorter than 2048 bits: {path} | always |
| `tls:weak-signature` | Medium | medium | TLS certificate signed with SHA-1 or MD5: {path} | always |

## Apache Tomcat (`tomcat`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `tomcat:admin-apps-deployed` | Medium | medium | Tomcat manager or host-manager application deployed: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:ajp-exposed` | High | medium | Tomcat AJP port reachable from the network | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:ajp-secret-disabled` | High | medium | Tomcat AJP connector accepts requests without a secret (Ghostcat) | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:conf-world-writable` | High | medium | Tomcat configuration writable by any user: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:default-credentials` | Critical | basic | Tomcat user with a default or well-known password | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:directory-listings` | Medium | medium | Tomcat DefaultServlet directory listings enabled | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:examples-deployed` | Medium | medium | Tomcat examples application deployed: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:manager-no-remote-addr` | High | medium | Tomcat manager is not restricted to localhost: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:runs-as-root` | High | medium | Tomcat service runs as root | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:shutdown-port` | Low | medium | Tomcat shutdown port enabled with the default command | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:users-world-readable` | High | medium | Tomcat tomcat-users.xml readable by any user: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:webapps-world-writable` | High | medium | Tomcat webapps directory writable by any user: {path} | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |
| `tomcat:xpoweredby` | Low | medium | Tomcat advertises itself in X-Powered-By | (package tomcat\|tomcat9\|tomcat10\|tomcat8\|tomcat-webapps or file /etc/tomcat*/server.xml\|/opt/tomcat*/conf/server.xml\|/opt/apache-tomcat*/conf/server.xml\|/usr/local/tomcat*/conf/server.xml) |

## VPN configuration (WireGuard, OpenVPN) (`vpn`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `openvpn:compression` | Medium | medium | OpenVPN compresses tunnel traffic (VORACLE) | package openvpn |
| `openvpn:duplicate-cn` | Medium | medium | OpenVPN allows several clients with the same certificate | package openvpn |
| `openvpn:key-perms` | High | medium | OpenVPN private key is readable by other users | package openvpn |
| `openvpn:no-privilege-drop` | Low | strict | OpenVPN server keeps root privileges | package openvpn |
| `openvpn:no-tls-auth` | Low | medium | OpenVPN server has no tls-auth/tls-crypt | package openvpn |
| `openvpn:script-security-3` | Low | medium | OpenVPN passes passwords to scripts (script-security 3) | package openvpn |
| `openvpn:tls-version-min` | Low | strict | OpenVPN does not require TLS 1.2 | package openvpn |
| `openvpn:weak-auth` | High | medium | OpenVPN data channel uses no or MD5 HMAC | package openvpn |
| `openvpn:weak-cipher` | High | medium | OpenVPN uses a weak or no data cipher | package openvpn |
| `wireguard:config-owner` | High | medium | WireGuard config is not owned by root | (package wireguard-tools\|wireguard or file /etc/wireguard/*.conf) |
| `wireguard:config-perms` | High | basic | WireGuard config with private key is readable by other users | (package wireguard-tools\|wireguard or file /etc/wireguard/*.conf) |
| `wireguard:dir-perms` | Low | strict | /etc/wireguard is accessible to other users | file /etc/wireguard |
| `wireguard:key-file-perms` | High | medium | WireGuard private key file is readable by other users | (package wireguard-tools\|wireguard or file /etc/wireguard) |
| `wireguard:module-missing` | Medium | - | wireguard module loaded but not installed for the running kernel (VPN breaks on next module reload/reboot) | - |
| `wireguard:stale-peer` | Low | - | WireGuard peer that never completed a handshake or not for rules.wireguard_stale_days (default 90) | - |

## Go rule (`web-exposure`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `tls:cert-expiry` | High | - | TLS certificate referenced by nginx is expired or expires within 14 days | - |
| `web:error-page-php` | Low | - | error_page routed to a .php script | - |
| `web:fastcgi-dead` | High | - | nginx fastcgi_pass points at a missing socket or a port nothing listens on | - |
| `web:origin-exposed` | Medium | - | vhost is set up for Cloudflare but the origin accepts direct connections from anywhere | - |
| `web:php-no-try-files` | Medium | - | PHP location without try_files $uri =404 (path-info / arbitrary file execution with cgi.fix_pathinfo) | - |
| `web:php-writable-dir` | High | - | Directory writable by the web/PHP user inside a server whose PHP location would execute uploaded .php files | - |
| `web:phpinfo` | Medium | - | phpinfo() page under a document root | - |
| `web:sensitive-file` | High | - | Secrets, VCS metadata, dumps, backups, keys or AI-agent notes (CLAUDE.md/AGENTS.md) under an nginx/httpd document root | - |
| `web:shell-stub` | High | - | PHP code calling shell_exec/system/passthru/proc_open in a file without a .php extension under a document root | - |

## Go rule (`web-server`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `apache` | High | - | Apache hardening: ServerTokens/Signature, TLS, TRACE, indexes | - |
| `nginx` | High | - | nginx.conf hardening: server_tokens, TLS protocols/ciphers, security headers, autoindex | - |

## Web applications (WordPress, Laravel, Nextcloud, Drupal, Joomla, Magento, phpMyAdmin) (`webapps`)

| ID | Severity | Level | Detects | Applies if |
|---|---|---|---|---|
| `adminer:present` | High | medium | Adminer database console in a web directory: {path} | file /var/www\|/srv/www\|/usr/share/nginx/html |
| `composer:auth-world-readable` | Medium | medium | Composer auth.json readable by any local user: {path} | file /root/.composer/auth.json\|/root/.config/composer/auth.json\|/home/*/.composer/auth.json\|/home/*/.config/composer/auth.json\|/var/www/*/auth.json\|/var/www/*/*/auth.json |
| `drupal:settings-world-readable` | High | medium | Drupal settings.php readable by any local user: {path} | file /var/www/*/sites/default/settings.php\|/var/www/*/*/sites/default/settings.php\|/srv/www/*/sites/default/settings.php |
| `drupal:settings-writable` | High | medium | Drupal settings.php writable by group or others: {path} | file /var/www/*/sites/default/settings.php\|/var/www/*/*/sites/default/settings.php\|/srv/www/*/sites/default/settings.php |
| `joomla:config-world-readable` | High | medium | Joomla configuration.php readable by any local user: {path} | file /var/www/*/configuration.php\|/var/www/*/*/configuration.php; file /var/www/*/administrator/manifests\|/var/www/*/*/administrator/manifests |
| `laravel:app-debug` | High | medium | Laravel APP_DEBUG enabled | file /var/www/*/artisan\|/var/www/*/*/artisan\|/srv/www/*/artisan |
| `laravel:app-env-not-production` | Medium | medium | Laravel APP_ENV is not production | file /var/www/*/artisan\|/var/www/*/*/artisan\|/srv/www/*/artisan |
| `laravel:env-world-readable` | High | medium | Laravel .env readable by any local user: {path} | file /var/www/*/artisan\|/var/www/*/*/artisan\|/srv/www/*/artisan |
| `laravel:storage-world-writable` | Medium | medium | Laravel storage/cache directory writable by any user: {path} | file /var/www/*/artisan\|/var/www/*/*/artisan\|/srv/www/*/artisan |
| `magento:env-world-readable` | High | medium | Magento app/etc/env.php readable by any local user: {path} | file /var/www/*/app/etc/env.php\|/var/www/*/*/app/etc/env.php |
| `nextcloud:config-world-readable` | High | medium | Nextcloud config.php readable by any local user: {path} | file /var/www/nextcloud/config/config.php\|/var/www/html/nextcloud/config/config.php\|/var/www/*/nextcloud/config/config.php\|/srv/www/nextcloud/config/config.php\|/usr/share/nginx/nextcloud/config/config.php |
| `nextcloud:data-in-webroot` | Low | medium | Nextcloud data directory inside the web root: {path} | file /var/www/nextcloud/config/config.php\|/var/www/html/nextcloud/config/config.php\|/var/www/*/nextcloud/config/config.php\|/srv/www/nextcloud/config/config.php\|/usr/share/nginx/nextcloud/config/config.php |
| `nextcloud:debug-enabled` | Medium | medium | Nextcloud debug mode enabled: {path} | file /var/www/nextcloud/config/config.php\|/var/www/html/nextcloud/config/config.php\|/var/www/*/nextcloud/config/config.php\|/srv/www/nextcloud/config/config.php\|/usr/share/nginx/nextcloud/config/config.php |
| `phpmyadmin:allow-no-password` | High | medium | phpMyAdmin allows logins without a password | file /etc/phpmyadmin/config.inc.php\|/etc/phpMyAdmin/config.inc.php\|/usr/share/phpmyadmin/config.inc.php\|/var/www/*/phpmyadmin/config.inc.php\|/var/www/phpmyadmin/config.inc.php |
| `phpmyadmin:auth-type-config` | Critical | medium | phpMyAdmin logs everyone in automatically (auth_type config) | file /etc/phpmyadmin/config.inc.php\|/etc/phpMyAdmin/config.inc.php\|/usr/share/phpmyadmin/config.inc.php\|/var/www/*/phpmyadmin/config.inc.php\|/var/www/phpmyadmin/config.inc.php |
| `pterodactyl:wings-config-readable` | High | medium | Pterodactyl Wings configuration readable by any user | file /etc/pterodactyl/config.yml |
| `wordpress:auto-updates-disabled` | Medium | medium | WordPress automatic updates disabled: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:config-world-readable` | High | medium | WordPress wp-config.php readable by any local user: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:config-world-writable` | Critical | medium | WordPress wp-config.php writable by any local user: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:db-root-user` | Medium | medium | WordPress connects to the database as root: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:debug-enabled` | Medium | medium | WordPress WP_DEBUG enabled: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:debug-log-present` | Medium | medium | WordPress debug.log in the web root: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:default-salts` | High | medium | WordPress authentication keys/salts never set: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:file-edit-enabled` | Medium | medium | WordPress built-in theme/plugin editor enabled: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:php-in-uploads` | High | medium | PHP file in WordPress uploads: {path} | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |
| `wordpress:xmlrpc-not-blocked` | Low | medium | WordPress xmlrpc.php is not blocked | file /var/www/wp-config.php\|/var/www/*/wp-config.php\|/var/www/*/*/wp-config.php\|/srv/www/*/wp-config.php\|/srv/www/*/*/wp-config.php\|/usr/share/nginx/html/wp-config.php\|/home/*/public_html/wp-config.php |

## How checks read the host

All checks read through `rules.Host`: files are host paths mapped under `rules.root` (default `/`), tools run with a 20 s timeout, and a missing file or tool means "skipped" or "not applicable", never a failed scan or a guessed finding. Nothing is modified. Pack checks can only run commands from a fixed read-only allowlist (`sshd -T`, `nginx -T`, `systemctl show`, `docker inspect`, ...). Evidence is redacted: values of password/token/secret-like keys, private keys, URL credentials and known token formats are masked. The only check that executes inside something else is `container:php-upload-progress` (`docker exec ... php -r`), which is why it is opt-in.
