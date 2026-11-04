<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/** Lightweight host-independent security posture, SBOM and tamper-evident audit chain. */
class SWPS_Security_Posture {
    const INVENTORY = 'swps_sbom_inventory';
    const CHAIN     = 'swps_incident_chain';

    public static function init() {
        add_action( 'swps_daily_cron', array( __CLASS__, 'audit' ) );
        add_action( 'admin_init', array( __CLASS__, 'install_early_waf' ) );
        add_action( 'admin_init', array( __CLASS__, 'block_plugin_install_screen' ), 0 );
        add_filter( 'upgrader_pre_install', array( __CLASS__, 'block_plugin_install' ), 10, 2 );
        add_action( 'upgrader_process_complete', array( __CLASS__, 'consume_plugin_install_grant' ), 10, 2 );
        add_action( 'wp_ajax_swps_request_plugin_install_code', array( __CLASS__, 'ajax_request_plugin_install_code' ) );
        add_action( 'wp_ajax_swps_approve_plugin_install', array( __CLASS__, 'ajax_approve_plugin_install' ) );
        add_action( 'wp_ajax_swps_approve_plugin_install_password', array( __CLASS__, 'ajax_approve_plugin_install_password' ) );
        self::report_guard_reactivation();
    }

    private static function code_key( $user_id ) { return 'swps_plugin_install_code_' . (int) $user_id; }
    private static function grant_key( $user_id ) { return 'swps_plugin_install_grant_' . (int) $user_id; }

    /** A new plugin requires both an authorised WP admin and the security-email code. */
    private static function has_plugin_install_grant() {
        return (bool) get_transient( self::grant_key( get_current_user_id() ) );
    }

    public static function ajax_request_plugin_install_code() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can( 'install_plugins' ) ) wp_send_json_error( 'Unauthorized.' );
        $user_id = get_current_user_id();
        if ( get_transient( 'swps_plugin_install_code_rate_' . $user_id ) ) wp_send_json_error( 'Please wait one minute before requesting another code.' );
        $to = sanitize_email( (string) ( get_option( 'swps_settings', array() )['alert_email'] ?? get_option( 'admin_email' ) ) );
        if ( ! is_email( $to ) ) wp_send_json_error( 'A valid security alert email is required first.' );

        $code = (string) random_int( 100000, 999999 );
        set_transient( self::code_key( $user_id ), wp_hash_password( $code ), 10 * MINUTE_IN_SECONDS );
        set_transient( 'swps_plugin_install_code_rate_' . $user_id, 1, MINUTE_IN_SECONDS );
        $sent = wp_mail( $to, '[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] Plugin-install approval code', "A request was made to install a new WordPress plugin.\n\nApproval code: {$code}\n\nThis code expires in 10 minutes. Do not share it.\nSite: " . home_url() );
        if ( ! $sent ) {
            SWPS_Activity_Log::add( 'plugin_install_code_failed', 'critical', 'Plugin-install approval code could not be handed to wp_mail(); SMTP/mail transport needs attention.' );
            wp_send_json_error( 'Email could not be sent. Use current-admin password approval below and fix SMTP before relying on alerts.' );
        }
        SWPS_Activity_Log::add( 'plugin_install_code_requested', 'warning', 'New-plugin install approval code requested by user #' . $user_id . '.' );
        wp_send_json_success( 'Approval code sent to the security alert email.' );
    }

    public static function ajax_approve_plugin_install() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can( 'install_plugins' ) ) wp_send_json_error( 'Unauthorized.' );
        $user_id = get_current_user_id();
        $hash = get_transient( self::code_key( $user_id ) );
        $code = preg_replace( '/\D/', '', (string) wp_unslash( $_POST['code'] ?? '' ) );
        if ( ! $hash || strlen( $code ) !== 6 || ! wp_check_password( $code, $hash ) ) wp_send_json_error( 'Invalid or expired approval code.' );
        delete_transient( self::code_key( $user_id ) );
        set_transient( self::grant_key( $user_id ), 1, 10 * MINUTE_IN_SECONDS );
        SWPS_Activity_Log::add( 'plugin_install_approved', 'warning', 'One new-plugin installation was approved for user #' . $user_id . ' for 10 minutes.' );
        wp_send_json_success( 'New-plugin installation is allowed for 10 minutes.' );
    }

    /**
     * SMTP-independent recovery path. It deliberately re-checks the current
     * administrator password; an attacker with only a stolen browser cookie
     * cannot unlock new plugin installation through this route.
     */
    public static function ajax_approve_plugin_install_password() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can( 'install_plugins' ) ) wp_send_json_error( 'Unauthorized.' );
        $user_id = get_current_user_id();
        $rate_key = 'swps_plugin_install_password_attempts_' . $user_id;
        if ( (int) get_transient( $rate_key ) >= 5 ) wp_send_json_error( 'Too many incorrect password attempts. Wait 5 minutes.' );
        $password = (string) wp_unslash( $_POST['password'] ?? '' );
        $user = wp_get_current_user();
        if ( ! $user || ! $password || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
            set_transient( $rate_key, (int) get_transient( $rate_key ) + 1, 5 * MINUTE_IN_SECONDS );
            SWPS_Activity_Log::add( 'plugin_install_password_failed', 'warning', 'Incorrect password entered for new-plugin installation approval by user #' . $user_id . '.' );
            wp_send_json_error( 'Current administrator password was not accepted.' );
        }
        delete_transient( $rate_key );
        set_transient( self::grant_key( $user_id ), 1, 10 * MINUTE_IN_SECONDS );
        SWPS_Activity_Log::add( 'plugin_install_approved_password', 'warning', 'New-plugin installation approved after current-password verification by user #' . $user_id . ' for 10 minutes.' );
        wp_send_json_success( 'New-plugin installation is allowed for 10 minutes.' );
    }

    public static function block_plugin_install_screen() {
        if ( ! current_user_can( 'install_plugins' ) || self::has_plugin_install_grant() ) return;
        $script = basename( (string) ( $_SERVER['PHP_SELF'] ?? '' ) );
        $action = sanitize_key( wp_unslash( $_REQUEST['action'] ?? '' ) );
        if ( $script === 'plugin-install.php' || ( $script === 'update.php' && in_array( $action, array( 'install-plugin', 'upload-plugin' ), true ) ) ) {
            wp_die( 'New plugin installation is locked. Go to WP Secure Pro → Settings and approve it with the security-email code first.', 'Plugin Installation Locked', array( 'response' => 403 ) );
        }
    }

    public static function block_plugin_install( $response, $hook_extra ) {
        if ( ( $hook_extra['type'] ?? '' ) === 'plugin' && ( $hook_extra['action'] ?? '' ) === 'install' && ! self::has_plugin_install_grant() ) {
            return new WP_Error( 'swps_plugin_install_locked', 'New plugin installation is locked. Approve it from WP Secure Pro Settings using the security-email code.' );
        }
        return $response;
    }

    public static function consume_plugin_install_grant( $upgrader, $hook_extra ) {
        if ( ( $hook_extra['type'] ?? '' ) === 'plugin' && ( $hook_extra['action'] ?? '' ) === 'install' ) {
            delete_transient( self::grant_key( get_current_user_id() ) );
        }
    }

    /** Record a MU-guard recovery after the normal plugin is loaded. */
    public static function report_guard_reactivation() {
        $time = (int) get_option( 'swps_guard_reactivated_at', 0 );
        if ( ! $time ) return;
        delete_option( 'swps_guard_reactivated_at' );
        $message = 'WP Secure Pro was deactivated but the MU self-protection guard restored it automatically at ' . wp_date( 'Y-m-d H:i:s', $time ) . '.';
        if ( class_exists( 'SWPS_Activity_Log' ) ) SWPS_Activity_Log::add( 'security_plugin_reactivated', 'critical', $message );
        if ( class_exists( 'SWPS_Email_Alerts' ) ) SWPS_Email_Alerts::send_alert( 'CRITICAL: WP Secure Pro reactivated itself', $message . "\nSite: " . get_site_url() );
    }

    public static function install_early_waf() {
        if ( ! defined( 'WPMU_PLUGIN_DIR' ) || ! is_dir( WPMU_PLUGIN_DIR ) && ! wp_mkdir_p( WPMU_PLUGIN_DIR ) ) return false;
        $source = SWPS_PLUGIN_DIR . 'mu-plugins/wp-secure-pro-early-waf.php';
        $target = trailingslashit( WPMU_PLUGIN_DIR ) . 'wp-secure-pro-early-waf.php';
        if ( ! is_readable( $source ) || ( file_exists( $target ) && hash_file( 'sha256', $source ) === hash_file( 'sha256', $target ) ) ) return true;
        return @copy( $source, $target );
    }

    public static function audit() {
        $inventory = self::inventory();
        $old = get_option( self::INVENTORY, array() );
        update_option( self::INVENTORY, $inventory, false );
        if ( ! empty( $old['hash'] ) && ! hash_equals( $old['hash'], $inventory['hash'] ) ) {
            self::event( 'inventory_changed', 'warning', 'Plugin/theme inventory changed outside the recorded baseline.' );
        }
        $findings = self::filesystem_findings();
        foreach ( $findings as $finding ) self::event( 'filesystem_hardening', 'critical', $finding );
        self::install_early_waf();
    }

    public static function inventory() {
        if ( ! function_exists( 'get_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = array();
        foreach ( get_plugins() as $file => $data ) $plugins[$file] = array( 'version' => (string) $data['Version'], 'active' => is_plugin_active( $file ) );
        $themes = array();
        foreach ( wp_get_themes() as $slug => $theme ) $themes[$slug] = array( 'version' => (string) $theme->get( 'Version' ), 'active' => get_stylesheet() === $slug );
        ksort( $plugins ); ksort( $themes );
        $data = array( 'generated_at' => time(), 'wordpress' => get_bloginfo( 'version' ), 'php' => PHP_VERSION, 'plugins' => $plugins, 'themes' => $themes );
        $data['hash'] = hash_hmac( 'sha256', wp_json_encode( $data ), wp_salt( 'auth' ) );
        return $data;
    }

    private static function filesystem_findings() {
        $findings = array();
        foreach ( array( ABSPATH . 'wp-config.php', WP_CONTENT_DIR ) as $path ) {
            if ( file_exists( $path ) && ( fileperms( $path ) & 0x0002 ) ) $findings[] = 'World-writable path detected: ' . $path;
        }
        $uploads = wp_upload_dir();
        if ( ! empty( $uploads['basedir'] ) && is_dir( $uploads['basedir'] ) ) {
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $uploads['basedir'], FilesystemIterator::SKIP_DOTS ) );
            $checked = 0;
            foreach ( $it as $file ) {
                if ( ++$checked > 10000 ) break;
                if ( $file->isFile() && preg_match( '/\.(php[0-9s]?|phtml)$/i', $file->getFilename() ) && ! self::is_known_safe_upload_php( $file->getPathname(), $uploads['basedir'] ) ) {
                    $findings[] = 'Executable file in uploads: ' . $file->getPathname();
                }
            }
        }
        return array_slice( array_unique( $findings ), 0, 50 );
    }

    private static function is_known_safe_upload_php( $path, $uploads_dir ) {
        $relative = ltrim( str_replace( wp_normalize_path( $uploads_dir ), '', wp_normalize_path( $path ) ), '/' );
        $content  = @file_get_contents( $path, false, null, 0, 512 );
        // WordPress and many plugins place a non-executable index.php to
        // prevent directory listing. It is not a webshell.
        if ( basename( $relative ) === 'index.php' && preg_match( '/^<\?php\s*(\/\/\s*Silence is golden\.)?\s*(exit;)?\s*$/is', (string) $content ) ) return true;
        // MetForm legitimately caches icon arrays as PHP in this precise,
        // non-web-executable cache location. Do not mask arbitrary PHP files.
        return (bool) preg_match( '#^metform/cache/icons/font-awesome-[a-f0-9]{16}\.php$#i', $relative )
            && strpos( (string) $content, 'Generated by MetForm' ) !== false
            && strpos( (string) $content, "defined( 'ABSPATH' ) || exit;" ) !== false
            && strpos( (string) $content, 'return array') !== false;
    }

    private static function event( $type, $severity, $message ) {
        $chain = get_option( self::CHAIN, array() );
        $previous = empty( $chain ) ? '' : end( $chain )['hash'];
        $event = array( 'time' => time(), 'type' => $type, 'severity' => $severity, 'message' => $message, 'previous' => $previous );
        $event['hash'] = hash_hmac( 'sha256', wp_json_encode( $event ), wp_salt( 'auth' ) );
        $chain[] = $event;
        update_option( self::CHAIN, array_slice( $chain, -1000 ), false );
        if ( class_exists( 'SWPS_Activity_Log' ) ) SWPS_Activity_Log::add( $type, $severity, $message );
    }
}
