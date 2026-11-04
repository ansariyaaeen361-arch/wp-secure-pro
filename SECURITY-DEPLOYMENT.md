# WP Secure Pro 2.0.8 hardening deployment

1. Revoke every GitHub token that was ever included in an earlier release.
   A source-distributed token must be considered compromised.
2. Copy `mu-plugins/wp-secure-pro-early-waf.php` to
   `wp-content/mu-plugins/wp-secure-pro-early-waf.php` on every site. Create
   `mu-plugins` if needed. Normal plugins cannot guarantee pre-plugin loading.
3. If the site is behind Cloudflare, a load balancer, or a reverse proxy, add
   only its *actual source IPs* to the `trusted_proxy_ips` setting. Leave it
   empty for direct-origin sites. Never add broad CIDRs until CIDR support has
   been explicitly configured.
4. The GitHub updater is intentionally fail-closed, but needs no per-site
   configuration. Its public Ed25519 verification key is embedded in the
   plugin. Add the matching private key as the GitHub repository secret
   `SWPS_UPDATE_SIGNING_PRIVATE_KEY`; the included release workflow creates a
   ZIP and `<release-zip-name>.sig` automatically whenever a `v*` tag is
   pushed. Unsigned releases will not install.
5. The update repository must be public for zero-config site updates. If it
   must remain private, use a separate public release-only repository or an
   authenticated update proxy; do not embed a GitHub access token in the ZIP.
6. Configure an off-server, encrypted backup with retention/immutability at
   the host or object-storage level. A WordPress plugin cannot make backups
   immutable against a server-root compromise.

The FIM no longer silently accepts non-core file changes. Review and explicitly
trust legitimate plugin/theme updates after every deployment.
