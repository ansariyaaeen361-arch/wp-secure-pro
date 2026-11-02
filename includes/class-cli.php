<?php
if ( ! defined( 'ABSPATH' ) ) exit;
if ( ! defined('WP_CLI') || ! WP_CLI ) return;

/**
 * WP Secure Pro WP-CLI commands.
 * Usage: wp swps <command>
 */
class SWPS_CLI {

    /**
     * Run malware scan.
     * ## EXAMPLES
     *   wp swps scan
     */
    public function scan( $args, $assoc ) {
        WP_CLI::log('Running WP Secure Pro malware scan...');
        $results = SWPS_Scanner::run_scan();
        $threats = $results['threats'] ?? array();
        if (empty($threats)) {
            WP_CLI::success('No threats found. Site is clean.');
        } else {
            WP_CLI::warning(count($threats) . ' threat(s) found:');
            foreach ($threats as $t) {
                WP_CLI::log('  [' . strtoupper($t['type']) . '] ' . $t['file'] . ' — ' . $t['reason']);
            }
        }
    }

    /**
     * File integrity check.
     * ## OPTIONS
     * [--baseline]
     *   : Create a new baseline instead of scanning.
     * ## EXAMPLES
     *   wp swps fim
     *   wp swps fim --baseline
     */
    public function fim( $args, $assoc ) {
        if ( ! empty($assoc['baseline']) ) {
            WP_CLI::log('Creating file integrity baseline...');
            $count = SWPS_File_Integrity::create_baseline();
            WP_CLI::success("Baseline created with $count files.");
            return;
        }
        WP_CLI::log('Running file integrity scan...');
        $result  = SWPS_File_Integrity::run_scan();
        $changes = $result['changes'] ?? array();
        if (empty($changes)) {
            WP_CLI::success('No file changes detected.');
        } else {
            WP_CLI::warning(count($changes) . ' change(s) detected:');
            foreach ($changes as $c) {
                WP_CLI::log('  [' . strtoupper($c['type']) . '] ' . $c['file']);
            }
        }
    }

    /**
     * Block an IP address.
     * ## OPTIONS
     * <ip>
     *   : The IP address to block.
     * [--reason=<reason>]
     *   : Reason for blocking.
     * [--duration=<minutes>]
     *   : Duration in minutes. 0 = permanent.
     * ## EXAMPLES
     *   wp swps block-ip 1.2.3.4 --reason="Manual block" --duration=1440
     */
    public function block_ip( $args, $assoc ) {
        $ip       = $args[0] ?? '';
        $reason   = $assoc['reason']   ?? 'WP-CLI manual block';
        $duration = intval($assoc['duration'] ?? 0);

        if ( ! filter_var($ip, FILTER_VALIDATE_IP) ) {
            WP_CLI::error("Invalid IP address: $ip");
        }
        SWPS_IP_Blocker::block_ip($ip, $reason, $duration);
        WP_CLI::success("IP $ip blocked" . ($duration > 0 ? " for $duration minutes." : " permanently."));
    }

    /**
     * Unblock an IP address.
     * ## EXAMPLES
     *   wp swps unblock-ip 1.2.3.4
     */
    public function unblock_ip( $args, $assoc ) {
        $ip = $args[0] ?? '';
        if ( ! filter_var($ip, FILTER_VALIDATE_IP) ) WP_CLI::error("Invalid IP: $ip");
        SWPS_IP_Blocker::unblock_ip($ip);
        WP_CLI::success("IP $ip unblocked.");
    }

    /**
     * List blocked IPs.
     * ## EXAMPLES
     *   wp swps list-blocked
     */
    public function list_blocked( $args, $assoc ) {
        global $wpdb;
        $ips = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}swps_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY blocked_at DESC LIMIT 50", ARRAY_A);
        if (empty($ips)) { WP_CLI::success('No IPs currently blocked.'); return; }
        WP_CLI\Utils\format_items('table', $ips, array('ip_address','reason','blocked_at','expires_at'));
    }

    /**
     * Check vulnerability status.
     * ## EXAMPLES
     *   wp swps vuln-scan
     */
    public function vuln_scan( $args, $assoc ) {
        WP_CLI::log('Running vulnerability scan...');
        $results = SWPS_Vuln_Scanner::run_scan(true);
        $total   = $results['total_vulns'] ?? 0;
        if ($total === 0) {
            WP_CLI::success('No vulnerabilities found.');
        } else {
            WP_CLI::warning("$total vulnerability/vulnerabilities found — update your plugins/themes.");
        }
    }

    /**
     * Check SSL certificate.
     * ## EXAMPLES
     *   wp swps check-ssl
     */
    public function check_ssl( $args, $assoc ) {
        WP_CLI::log('Checking SSL certificate...');
        $result = SWPS_SSL_Monitor::check_ssl(true);
        $days   = $result['days_remaining'] ?? 'N/A';
        $issuer = $result['issuer'] ?? 'Unknown';
        $expires= $result['expires'] ?? 'Unknown';
        WP_CLI::log("Issuer: $issuer | Expires: $expires | Days remaining: $days");
        if (is_numeric($days) && $days <= 0) WP_CLI::error('SSL EXPIRED!');
        elseif (is_numeric($days) && $days < 30) WP_CLI::warning("SSL expiring soon: $days days.");
        else WP_CLI::success("SSL is valid.");
    }

    /**
     * Send test notification.
     * ## OPTIONS
     * [--channel=<channel>]
     *   : slack, telegram, discord, email
     * ## EXAMPLES
     *   wp swps test-notify --channel=slack
     */
    public function test_notify( $args, $assoc ) {
        $channel = $assoc['channel'] ?? 'email';
        $result  = SWPS_Notifications::test($channel);
        $result ? WP_CLI::success("Test sent to $channel.") : WP_CLI::error("Failed — check settings.");
    }

    /**
     * Send security digest now.
     * ## OPTIONS
     * [--type=<type>]
     *   : daily or weekly
     * ## EXAMPLES
     *   wp swps digest --type=weekly
     */
    public function digest( $args, $assoc ) {
        $type = $assoc['type'] ?? 'weekly';
        SWPS_Report_Digest::send_digest($type);
        WP_CLI::success("$type digest sent.");
    }

    /**
     * Show plugin status.
     * ## EXAMPLES
     *   wp swps status
     */
    public function status( $args, $assoc ) {
        $settings = get_option('swps_settings', array());
        $fim      = SWPS_File_Integrity::get_stats();
        $sessions = SWPS_Session_Manager::get_stats();
        $ssl      = SWPS_SSL_Monitor::get_last_check();

        $items = array(
            array('Feature','Status'),
            array('WAF',           !empty($settings['waf_enabled']) ? 'ON ('.$settings['waf_mode'].' mode)' : 'OFF'),
            array('2FA',           !empty($settings['two_factor_enabled']) ? 'ON' : 'OFF'),
            array('Login URL',     !empty($settings['login_url']) ? $settings['login_url'] : 'Default'),
            array('GeoIP',         !empty($settings['geoip_enabled']) ? 'ON' : 'OFF'),
            array('File Monitor',  $fim['baseline_files'] > 0 ? $fim['baseline_files'].' files monitored' : 'No baseline'),
            array('Active Sessions', $sessions['total']),
            array('SSL Days Left', $ssl['days_remaining'] ?? 'Not checked'),
            array('Version',       SWPS_VERSION),
        );
        foreach (array_slice($items, 1) as $row) {
            WP_CLI::log(str_pad($row[0], 20) . $row[1]);
        }
    }
}

WP_CLI::add_command( 'swps', 'SWPS_CLI' );
