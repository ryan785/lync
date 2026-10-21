# Checks reference

Every non-CVE check Lync runs, by rule. The ID is the prefix of every finding the check emits (`web:sensitive-file` -> `web:sensitive-file:/var/www/site/.env`), so it is what you put in `rules.disable` / `rules.enable`. `lync checks` prints this list with the on/off state under your config.

Severity is the typical/maximum; several checks adjust it with context (see the description). "opt-in" checks run only when listed in `rules.enable`.

## Web exposure (nginx/httpd document roots and routing) (`web-exposure`)

| ID | Severity | Detects |
|---|---|---|
| `tls:cert-expiry` | High | TLS certificate referenced by nginx is expired or expires within 14 days |
| `web:error-page-php` | Low | error_page routed to a .php script |
| `web:fastcgi-dead` | High | nginx fastcgi_pass points at a missing socket or a port nothing listens on |
| `web:origin-exposed` | Medium | vhost is set up for Cloudflare but the origin accepts direct connections from anywhere |
| `web:php-no-try-files` | Medium | PHP location without try_files $uri =404 (path-info / arbitrary file execution with cgi.fix_pathinfo) |
| `web:php-writable-dir` | High | Directory writable by the web/PHP user inside a server whose PHP location would execute uploaded .php files |
| `web:phpinfo` | Medium | phpinfo() page under a document root |
| `web:sensitive-file` | High | Secrets, VCS metadata, dumps, backups, keys or AI-agent notes (CLAUDE.md/AGENTS.md) under an nginx/httpd document root |
| `web:shell-stub` | High | PHP code calling shell_exec/system/passthru/proc_open in a file without a .php extension under a document root |

## PHP configuration (`php`)

| ID | Severity | Detects |
|---|---|---|
| `php:allow-url-include` | High | allow_url_include=On enables remote file inclusion |
| `php:cgi-fix-pathinfo` | Low | cgi.fix_pathinfo=1 (default) with FPM |
| `php:disable-functions-empty` | Low | disable_functions is empty (no defense in depth against webshells) |
| `php:display-errors` | Medium | display_errors on: errors (paths, SQL) shown to visitors |
| `php:eol-branch` | High | PHP branch past upstream end-of-life (<= 8.1) |
| `php:expose-php` | Low | expose_php=On advertises the PHP version |
| `php:session-path` | Medium | session.save_path missing or not writable by the pool user |
| `php:upload-progress` | High | session.upload_progress.enabled is On (default) - exposure for CVE-2026-109618 / CVE-2026-109619 |

## Network exposure (`exposure`)

| ID | Severity | Detects |
|---|---|---|
| `checkmk:unrestricted` | Medium | Checkmk agent (6556) answers anyone: no only_from restriction and no TLS agent controller |
| `cockpit:enabled` | Low | Cockpit web console socket is enabled |
| `docker:published-bypass` | High | Docker-published port on 0.0.0.0/:: while DOCKER-USER is empty: reachable regardless of firewalld |
| `firewall:stale-open` | Low | firewalld zone opens a port/service that nothing listens on |
| `net:datastore-exposed` | High | Database/cache port (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached...) listening on a non-loopback address |
| `net:rpcbind-exposed` | Medium | rpcbind (111) listening on a non-loopback address |
| `redis:no-auth` | High | Redis config without requirepass/ACL users |

## System state and updates (`system`)

| ID | Severity | Detects |
|---|---|---|
| `mac:selinux-runtime-drift` | High | SELinux enforcing in /etc/selinux/config but permissive/disabled at runtime (setenforce 0) |
| `sys:boot-kernel-downgrade` | High | Boot default kernel is older than the running kernel: next reboot silently downgrades |
| `sys:kernel-repo` | Medium | Running kernel package comes from a disabled or unknown repo (e.g. elrepo kernel-ml with the repo off): no updates |
| `sys:reboot-required` | Medium | Running kernel is older than the newest installed kernel (patches not active until reboot) |
| `sys:uptime` | Low | Uptime over 180 days |
| `systemd:failed-unit` | Medium | systemd units in failed state (enabled ones rate higher) |
| `updates:no-auto` | Medium | No automatic security updates (dnf-automatic / unattended-upgrades absent or disabled) |
| `updates:pending-security` | High | Pending security advisories (dnf updateinfo, cache only), by severity with the oldest advisory |

## Access and privilege paths (`access`)

| ID | Severity | Detects |
|---|---|---|
| `account:ssh-perms` | High | ~/.ssh or authorized_keys writable by group/others or owned by another user |
| `account:sudo-nopasswd` | Medium | sudoers grants NOPASSWD (ALL = High) |
| `cron:writable-script` | Critical | Root cron job runs a script that non-root users can modify |
| `docker:group-members` | Medium | Users in the docker group (root-equivalent) |
| `docker:socket-perms` | Critical | docker.sock writable by non-root users outside the docker group |
| `fs:world-writable-dir` | High | World-writable directory (no sticky bit) under /etc, web roots or cron dirs |
| `secrets:world-readable` | High | Password/token-like keys in world-readable systemd units, compose files or .env files (key names only) |

## SSH (`ssh-config`)

| ID | Severity | Detects |
|---|---|---|
| `ssh` | High | sshd_config settings (root login, passwords, ciphers, MACs, KEX, forwarding...) |
| `ssh:root-password-login` | Critical | PermitRootLogin yes with password authentication (Critical without fail2ban/sshguard) |

## Runtimes and containers (`runtimes`)

| ID | Severity | Detects |
|---|---|---|
| `container:eol-base` | Medium | Image tag names an EOL runtime (postgres<=13, node<=20, php<=8.1, python<=3.9, mysql 5.x, redis<=6) |
| `container:image-age` | Medium | Running container image built longer ago than rules.image_max_age_days (default 365) |
| `container:latest-tag` | Low | Container runs an image referenced by :latest (or no tag): unpinned, unknown patch level |
| `container:php-upload-progress` | High | PHP inside running containers has session.upload_progress.enabled on (docker exec; opt-in) **(opt-in)** |
| `container:restart-loop` | Low | Container with restart policy always/unless-stopped that is exited or restarting repeatedly |
| `runtime:eol-node` | High | Running node process uses an end-of-life Node.js major (incl. nvm installs) |
| `runtime:eol-python` | Medium | Running python process uses an end-of-life CPython outside distro paths (pyenv, /usr/local, conda) |

## WireGuard (`vpn`)

| ID | Severity | Detects |
|---|---|---|
| `wireguard:module-missing` | Medium | wireguard module loaded but not installed for the running kernel (VPN breaks on next module reload/reboot) |
| `wireguard:stale-peer` | Low | WireGuard peer that never completed a handshake or not for rules.wireguard_stale_days (default 90) |

## Accounts (original) (`accounts`)

| ID | Severity | Detects |
|---|---|---|
| `account:empty-pwd` | Critical | Account with an empty password hash |
| `account:uid0` | Critical | Non-root account with UID 0 |

## Filesystem (original) (`filesystem`)

| ID | Severity | Detects |
|---|---|---|
| `fs:unexpected-setuid` | Medium | Setuid binaries outside the baseline |
| `fs:world-writable` | High | World-writable files under /etc, /usr/local, /opt |

## Network (original) (`network`)

| ID | Severity | Detects |
|---|---|---|
| `net:exposed` | Medium | TCP service listening on all interfaces (other than 22/80/443) |

## Firewall (original) (`firewall`)

| ID | Severity | Detects |
|---|---|---|
| `firewall:none-active` | High | No active host firewall |

## sysctl hardening (original) (`hardening`)

| ID | Severity | Detects |
|---|---|---|
| `hardening` | Medium | sysctl kernel/network hardening values |

## OS end-of-life (original) (`eol`)

| ID | Severity | Detects |
|---|---|---|
| `eol` | High | OS release past or near end-of-life (endoflife.date) |

## Web server hardening (original) (`web-server`)

| ID | Severity | Detects |
|---|---|---|
| `apache` | High | Apache hardening: ServerTokens/Signature, TLS, TRACE, indexes |
| `nginx` | High | nginx.conf hardening: server_tokens, TLS protocols/ciphers, security headers, autoindex |

## login.defs (original) (`login-defs`)

| ID | Severity | Detects |
|---|---|---|
| `login-defs` | Low | /etc/login.defs password aging and hashing |

## Mount options (original) (`mount`)

| ID | Severity | Detects |
|---|---|---|
| `mount` | Low | Missing nodev/nosuid/noexec on /tmp, /dev/shm, /var/tmp... |

## SELinux/AppArmor (original) (`mac`)

| ID | Severity | Detects |
|---|---|---|
| `mac` | Medium | SELinux/AppArmor disabled or permissive |

## How checks read the host

All new checks read through `rules.Host`: files are host paths mapped under `rules.root` (default `/`), tools run with a 20 s timeout, and a missing file or tool means "no finding", never a failed scan. Nothing is modified. The only check that executes inside something else is `container:php-upload-progress` (`docker exec ... php -r`), which is why it is opt-in. Secret findings report file paths and key names, never values.
