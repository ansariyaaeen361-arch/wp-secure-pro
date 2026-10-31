<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_WAF {

    // SQL Injection patterns
    private static $sqli = array(
        '/(\%27)|(\')|(\-\-)|(\%23)|(\#)/ix',
        '/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/ix',
        '/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix',
        '/((\%27)|(\'))union/ix',
        '/exec(\s|\+)+(s|x)p\w+/ix',
        '/UNION(.*)SELECT/is',
        '/SELECT(.*)FROM/is',
        '/INSERT(.*)INTO/is',
        '/DROP(.*)TABLE/is',
        '/UPDATE(.*)SET/is',
        '/DELETE(.*)FROM/is',
        '/LOAD_FILE|INTO\s+OUTFILE/is',
        '/benchmark\s*\(.*\)/is',
        '/sleep\s*\(\s*\d+\s*\)/is',
        '/\bOR\b\s+\d+\s*=\s*\d+/is',
        '/\bAND\b\s+\d+\s*=\s*\d+/is',
        '/\/\*.*\*\//is',
        '/xp_cmdshell/is',
    );

    // XSS patterns
    private static $xss = array(
        '/<script[^>]*>.*?<\/script>/is',
        '/javascript\s*:/is',
        '/on(load|error|click|mouse|focus|blur|key|submit|change|scroll)\s*=/is',
        '/<iframe[^>]*>/is',
        '/<object[^>]*>/is',
        '/<embed[^>]*>/is',
        '/expression\s*\(/is',
        '/vbscript\s*:/is',
        '/data\s*:\s*text\/html/is',
        '/<svg[^>]*on\w+/is',
        '/\x00/', // null byte
    );

    // LFI / Path Traversal
    private static $lfi = array(
        '/\.\.\//',
        '/\.\.\\\\/',
        '/etc\/passwd/i',
        '/etc\/shadow/i',
        '/proc\/self\/environ/i',
        '/\/var\/log\//i',
        '/php:\/\/input/i',
        '/php:\/\/filter/i',
        '/data:\/\//i',
        '/expect:\/\//i',
    );

    // RFI (Remote File Inclusion)
    private static $rfi = array(
        '/=http:\/\//i',
        '/=https:\/\//i',
        '/=ftp:\/\//i',
        '/=\/\/[a-z0-9]/i',
    );

    // Bad bots / user agents
    private static $bad_bots = array(
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
        'dirbuster', 'gobuster', 'wfuzz', 'burpsuite',
        'acunetix', 'nessus', 'openvas', 'w3af',
        'havij', 'pangolin', 'safe3', 'libwww-perl',
        'python-requests', 'curl/', 'wget/', 'go-http-client',
        'scrapy', 'phantomjs', 'headless', 'metasploit',
        'commix', 'dropbear',
    );

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['waf_enabled'] ) ) return;

        // Run WAF at the earliest possible point
        add_action( 'init', array( __CLASS__, 'run' ), 1 );

        // Scan every uploaded file's content before WordPress accepts it —
        // runs for all users (including admins) since a malicious/compromised
        // account uploading a webshell is exactly what this should catch.
        add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'check_upload' ) );
    }

    /**
     * Rejects uploads whose content matches a known webshell/backdoor
     * signature, and double-extension tricks (e.g. shell.php.jpg) that could
     * let a disguised PHP file land in uploads on a misconfigured host.
     */
    public static function check_upload( $file ) {
        if ( ! empty( $file['error'] ) || empty( $file['tmp_name'] ) ) return $file;

        $name = strtolower( $file['name'] ?? '' );
        if ( preg_match( '/\.(php\d?|phtml|pht|phar)\./', $name ) || preg_match( '/\.(php\d?|phtml|pht|phar)$/', $name ) ) {
            $file['error'] = 'Upload rejected: executable file type is not allowed.';
            return $file;
        }

        $content = @file_get_contents( $file['tmp_name'] );
        if ( $content !== false && class_exists( 'SWPS_Scanner' ) ) {
            $threats = SWPS_Scanner::scan_content( $content );
            if ( ! empty( $threats ) ) {
                $ip = class_exists('SWPS_Login_Protection') ? SWPS_Login_Protection::get_client_ip() : ( $_SERVER['REMOTE_ADDR'] ?? '' );
                SWPS_Activity_Log::add( 'upload_blocked', 'critical', "Malicious upload blocked: {$file['name']} ($ip) — " . implode(', ', $threats) );
                $file['error'] = 'Upload rejected: file content matched a known malicious signature.';
            }
        }

        return $file;
    }

    public static function run() {
        // Skip for logged-in admins (whitelist)
        if ( is_user_logged_in() && current_user_can('manage_options') ) return;

        $ip = SWPS_Login_Protection::get_client_ip();

        // 1. Check blocked IP first (fastest check)
        if ( SWPS_IP_Blocker::is_blocked( $ip ) ) {
            self::block_request( 'Blocked IP', 'ip_blocked', $ip );
        }

        // 2. Bad bot check
        $ua = strtolower( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        foreach ( self::$bad_bots as $bot ) {
            if ( strpos( $ua, $bot ) !== false ) {
                self::block_request( "Bad bot detected: $bot", 'bad_bot', $ip );
            }
        }

        // 3. Collect all input to scan
        $inputs = array_merge(
            array_values( $_GET ),
            array_values( $_POST ),
            array( $_SERVER['REQUEST_URI'] ?? '' ),
            array( $_SERVER['HTTP_REFERER'] ?? '' ),
        );
        $input_str = implode( ' ', array_map( 'urldecode', $inputs ) );
        $input_str = stripslashes( $input_str );

        // 4. SQLi check
        foreach ( self::$sqli as $pattern ) {
            if ( preg_match( $pattern, $input_str ) ) {
                self::block_request( "SQL Injection attempt ($pattern)", 'sqli', $ip );
            }
        }

        // 5. XSS check
        foreach ( self::$xss as $pattern ) {
            if ( preg_match( $pattern, $input_str ) ) {
                self::block_request( "XSS attempt ($pattern)", 'xss', $ip );
            }
        }

        // 6. LFI check
        foreach ( self::$lfi as $pattern ) {
            if ( preg_match( $pattern, $input_str ) ) {
                self::block_request( "LFI/Path Traversal attempt ($pattern)", 'lfi', $ip );
            }
        }

        // 7. RFI check (only on specific params)
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        foreach ( self::$rfi as $pattern ) {
            if ( preg_match( $pattern, $uri ) ) {
                self::block_request( "RFI attempt ($pattern)", 'rfi', $ip );
            }
        }

        // 8. Fake Google/Bing bot check
        if ( strpos( $ua, 'googlebot' ) !== false || strpos( $ua, 'bingbot' ) !== false ) {
            if ( self::is_fake_crawler( $ip ) ) {
                self::block_request( "Fake crawler detected: $ua", 'fake_bot', $ip );
            }
        }
    }

    /**
     * Verifies a claimed Googlebot/Bingbot visitor the way Google and
     * Microsoft actually document: reverse-DNS the IP, confirm the
     * hostname belongs to the real crawler's domain, THEN forward-resolve
     * that hostname and confirm it maps back to the SAME IP. A single
     * reverse lookup alone (the previous check) can't rule out DNS
     * spoofing, and — the more common real-world failure — blindly trusts
     * whatever gethostbyaddr() returns even when DNS is slow/unavailable,
     * at which point it just echoes the IP back with no hostname at all,
     * which would have wrongly "convicted" a genuine Googlebot visit of
     * being fake. False negatives here (an attacker evades this one check)
     * still hit every other WAF rule; false positives here cost real SEO
     * traffic, so on any DNS uncertainty this fails OPEN — not fake.
     */
    private static function is_fake_crawler( $ip ) {
        $hostname = @gethostbyaddr( $ip );
        if ( ! $hostname || $hostname === $ip ) return false; // reverse DNS unavailable — don't convict on missing data

        $valid_suffixes = array( '.googlebot.com', '.google.com', '.search.msn.com' );
        $matched = false;
        foreach ( $valid_suffixes as $suffix ) {
            if ( substr( $hostname, -strlen($suffix) ) === $suffix ) { $matched = true; break; }
        }
        if ( ! $matched ) return true; // hostname doesn't belong to Google/Bing at all — genuinely fake

        // Forward-confirm: the claimed hostname must resolve back to this exact IP.
        $forward_ip = @gethostbyname( $hostname );
        if ( ! $forward_ip || $forward_ip === $hostname ) return false; // forward lookup unavailable — don't convict on missing data
        return $forward_ip !== $ip;
    }

    private static function block_request( $reason, $type, $ip ) {
        $settings = get_option( 'swps_settings', array() );

        // Log the blocked request
        SWPS_Activity_Log::add(
            'waf_blocked_' . $type,
            'warning',
            "WAF blocked: $reason | IP: $ip | URI: " . ( $_SERVER['REQUEST_URI'] ?? '' )
        );

        if ( class_exists('SWPS_Live_Traffic') ) {
            SWPS_Live_Traffic::log_attack( $ip, $reason );
        }

        // Auto-block IP if same IP keeps attacking
        global $wpdb;
        $recent = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}swps_activity_log
             WHERE ip_address = %s AND event_type LIKE 'waf_blocked_%' AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)",
            $ip
        ) );

        $threshold = (int) ( $settings['waf_auto_block_threshold'] ?? 5 );
        if ( $threshold < 1 ) $threshold = 5;

        if ( $recent >= $threshold ) {
            $already_blocked = SWPS_IP_Blocker::is_blocked( $ip );
            SWPS_IP_Blocker::block_ip( $ip, "Auto-blocked by WAF: $reason", 60 );
            if ( ! $already_blocked ) {
                SWPS_Notifications::get_instance()->send(
                    'waf_auto_block',
                    'SecureWP Shield: IP Auto-Blocked',
                    "IP $ip was automatically blocked after $recent malicious requests in 10 minutes.\nLast reason: $reason",
                    'critical'
                );
            }
        }

        if ( ! empty( $settings['waf_mode'] ) && $settings['waf_mode'] === 'learning' ) {
            return; // Learning mode: log only, don't block
        }

        // Block the request
        status_header( 403 );
        nocache_headers();
        die( '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>
            <h1>&#9888; Access Denied</h1>
            <p>Your request has been blocked by the security system.</p>
            <p>If you believe this is an error, please contact the site administrator.</p>
            <small>Reference: ' . esc_html( $type ) . ' | ' . date('Y-m-d H:i:s') . '</small>
        </body></html>' );
    }

    public static function get_stats() {
        global $wpdb;
        $rows = $wpdb->get_results(
            "SELECT event_type, COUNT(*) as cnt FROM {$wpdb->prefix}swps_activity_log
             WHERE event_type LIKE 'waf_blocked_%' GROUP BY event_type ORDER BY cnt DESC"
        );
        $total = 0;
        $types = array();
        foreach ( $rows as $r ) {
            $type_label = str_replace( 'waf_blocked_', '', $r->event_type );
            $types[ $type_label ] = (int) $r->cnt;
            $total += (int) $r->cnt;
        }
        return array( 'total' => $total, 'by_type' => $types );
    }

    public static function get_recent_blocks( $limit = 20 ) {
        global $wpdb;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}swps_activity_log
             WHERE event_type LIKE 'waf_blocked_%' ORDER BY created_at DESC LIMIT %d",
            $limit
        ) );
    }
}
