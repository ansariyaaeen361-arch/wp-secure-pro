<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Hardening {

    public static function init() {
        $h = get_option( 'swps_hardening', array() );

        if ( ! empty( $h['remove_wp_version'] ) )     add_filter( 'the_generator',       '__return_empty_string' );
        if ( ! empty( $h['remove_wp_version'] ) )     add_filter( 'wp_generator',        '__return_empty_string' );
        if ( ! empty( $h['disable_xmlrpc'] ) )        add_filter( 'xmlrpc_enabled',       '__return_false' );
        if ( ! empty( $h['disable_xmlrpc'] ) )        add_filter( 'xmlrpc_methods',       array( __CLASS__, 'empty_array' ) );
        if ( ! empty( $h['disable_file_edit'] ) )     self::disable_file_edit();
        if ( ! empty( $h['disable_rest_anon'] ) )     add_filter( 'rest_authentication_errors', array( __CLASS__, 'restrict_rest_api' ) );
        if ( ! empty( $h['remove_rsd_link'] ) )       remove_action( 'wp_head', 'rsd_link' );
        if ( ! empty( $h['remove_wlw_link'] ) )       remove_action( 'wp_head', 'wlwmanifest_link' );
        if ( ! empty( $h['remove_shortlink'] ) )      remove_action( 'wp_head', 'wp_shortlink_wp_head' );
        if ( ! empty( $h['remove_adjacent_links'] ) ) remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
        if ( ! empty( $h['remove_emoji'] ) )          self::disable_emojis();
        if ( ! empty( $h['disable_author_scan'] ) )   add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ) );
        if ( ! empty( $h['strong_passwords'] ) )      add_action( 'user_profile_update_errors', array( __CLASS__, 'enforce_strong_password' ), 10, 3 );
        if ( ! empty( $h['disable_pingback'] ) )      add_filter( 'wp_headers', array( __CLASS__, 'remove_x_pingback' ) );
        if ( ! empty( $h['comment_nofollow'] ) )      add_filter( 'pre_comment_approved', array( __CLASS__, 'check_comment_links' ), 10, 2 );
        if ( ! empty( $h['limit_login_page_access'] ) ) add_action( 'login_head', array( __CLASS__, 'restrict_login_ip' ) );
        if ( ! empty( $h['disable_directory_listing'] ) ) self::write_htaccess_no_listing();
        if ( ! empty( $h['block_sensitive_files'] ) )  self::write_htaccess_block_sensitive_files();
    }

    public static function get_defaults() {
        return array(
            'remove_wp_version'        => 1,
            'disable_xmlrpc'           => 1,
            'disable_file_edit'        => 1,
            'disable_rest_anon'        => 1,
            'remove_rsd_link'          => 1,
            'remove_wlw_link'          => 1,
            'remove_shortlink'         => 1,
            'remove_adjacent_links'    => 0,
            'remove_emoji'             => 0,
            'disable_author_scan'      => 1,
            'strong_passwords'         => 1,
            'disable_pingback'         => 1,
            'comment_nofollow'         => 0,
            'disable_directory_listing'=> 1,
            'limit_login_page_access'  => 0,
            'block_sensitive_files'    => 1,
        );
    }

    /* ----- Individual hardening methods ----- */

    private static function disable_file_edit() {
        if ( ! defined('DISALLOW_FILE_EDIT') ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }
    }

    public static function restrict_rest_api( $result ) {
        if ( ! empty( $result ) ) return $result;
        if ( is_user_logged_in() ) return $result;
        // Allow specific safe endpoints
        $request = $_SERVER['REQUEST_URI'] ?? '';
        // Fix: this blanket REST lockdown was also catching our OWN public,
        // independently-authenticated routes (Threat Feed Server, Multisite
        // Hub) — /wp-json/swps/v1/*, which enforce their own token checks —
        // so turning on "Restrict REST API" silently broke those features
        // with no indication why. Let our own namespace handle its own auth.
        if ( strpos( $request, '/wp-json/swps/v1/' ) !== false ) return $result;
        $safe    = array( '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages', '/wp-json/wp/v2/categories' );
        foreach ( $safe as $ep ) {
            if ( strpos( $request, $ep ) !== false ) return $result;
        }
        return new WP_Error( 'rest_disabled', 'REST API access restricted to authenticated users.', array('status' => 401) );
    }

    public static function empty_array() { return array(); }

    private static function disable_emojis() {
        remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
        remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
        remove_action( 'wp_print_styles', 'print_emoji_styles' );
        remove_action( 'admin_print_styles', 'print_emoji_styles' );
        remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
        remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
        remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
    }

    public static function block_author_scan() {
        if ( isset( $_GET['author'] ) && ! is_admin() ) {
            $ip = SWPS_Login_Protection::get_client_ip();
            SWPS_Activity_Log::add( 'author_scan_blocked', 'info', "Author scan blocked: ?author= from $ip" );
            wp_redirect( home_url(), 301 );
            exit;
        }
    }

    public static function enforce_strong_password( $errors, $update, $user ) {
        // Only validate when a new password is actually being set,
        // otherwise every profile save (email, name, etc.) would be blocked.
        if ( empty( $_POST['pass1'] ) ) return;
        $pass = (string) $_POST['pass1'];
        if ( strlen($pass) < 8 ) {
            $errors->add( 'pass', 'Password must be at least 8 characters long.' );
        }
        if ( ! preg_match('/[A-Z]/', $pass ) ) {
            $errors->add( 'pass', 'Password must contain at least one uppercase letter.' );
        }
        if ( ! preg_match('/[0-9]/', $pass ) ) {
            $errors->add( 'pass', 'Password must contain at least one number.' );
        }
    }

    public static function remove_x_pingback( $headers ) {
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    public static function check_comment_links( $approved, $comment_data ) {
        if ( substr_count( $comment_data['comment_content'], 'http' ) > 2 ) {
            return 'hold'; // Hold for moderation
        }
        return $approved;
    }

    public static function restrict_login_ip() {
        $settings = get_option( 'swps_settings', array() );
        $allowed  = array_filter( array_map( 'trim', explode( "\n", $settings['login_allowed_ips'] ?? '' ) ) );
        if ( empty($allowed) ) return;
        $ip = SWPS_Login_Protection::get_client_ip();
        foreach ( $allowed as $allowed_ip ) {
            if ( $ip === $allowed_ip ) return;
        }
        status_header(403);
        die('Access to login page restricted by IP.');
    }

    private static function write_htaccess_no_listing() {
        $htaccess = ABSPATH . '.htaccess';
        $marker   = 'SWPS No Directory Listing';
        $rules    = "Options -Indexes\n";
        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        insert_with_markers( $htaccess, $marker, $rules );
    }

    private static function write_htaccess_block_sensitive_files() {
        $htaccess = ABSPATH . '.htaccess';
        $marker   = 'SWPS Block Sensitive Files';
        $rules    = "<FilesMatch \"\\.(log|bak|backup|old|orig|save|swp|sql|sql\\.gz|env|ini|cfg|conf|dist|dump)(\\..*)?$\">\n"
                  . "    Order Allow,Deny\n"
                  . "    Deny from all\n"
                  . "    Require all denied\n"
                  . "</FilesMatch>\n"
                  . "<FilesMatch \"^(wp-config\\.php.*|error_log|debug\\.log)$\">\n"
                  . "    Order Allow,Deny\n"
                  . "    Deny from all\n"
                  . "    Require all denied\n"
                  . "</FilesMatch>\n";
        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        insert_with_markers( $htaccess, $marker, $rules );
    }

    /* ----- Apply bulk changes & generate report ----- */

    public static function apply_wp_config_hardening() {
        // Suggest wp-config.php changes (read-only advice)
        $suggestions = array(
            "define('DISALLOW_FILE_EDIT', true);"    => 'Disable file editing in admin',
            "define('DISALLOW_FILE_MODS', true);"    => 'Disable plugin/theme install',
            "define('FORCE_SSL_ADMIN', true);"        => 'Force SSL for admin',
            "define('WP_DEBUG', false);"              => 'Disable debug mode (production)',
            "define('WP_AUTO_UPDATE_CORE', true);"    => 'Enable core auto-updates',
        );

        // If debug logging is on and writing inside the webroot, suggest an
        // absolute path outside it — a file outside ABSPATH has no URL at
        // all, which is more reliable than relying on the host's .htaccess
        // (confirmed to be ignored on at least one OpenLiteSpeed setup).
        if ( defined('WP_DEBUG_LOG') && ( WP_DEBUG_LOG === true || ( is_string(WP_DEBUG_LOG) && strpos( WP_DEBUG_LOG, ABSPATH ) === 0 ) ) ) {
            $outside = dirname( rtrim( ABSPATH, '/\\' ) ) . '/logs/debug.log';
            $suggestions[ "define('WP_DEBUG_LOG', '$outside');" ] = 'Move debug log outside the webroot (currently publicly downloadable)';
        }

        return $suggestions;
    }

    public static function get_security_check_list() {
        $checks = array();

        // WP version exposed?
        $version_in_head = false;
        // We can't check rendered HTML here, but we can check the setting
        $h = get_option('swps_hardening', array());
        $checks[] = array(
            'label'  => 'WordPress version hidden',
            'status' => ! empty($h['remove_wp_version']),
            'fix'    => 'Enable "Remove WP Version" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'XML-RPC disabled',
            'status' => ! empty($h['disable_xmlrpc']),
            'fix'    => 'Enable "Disable XML-RPC" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'File editing disabled',
            'status' => defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
            'fix'    => 'Add define(\'DISALLOW_FILE_EDIT\', true); to wp-config.php',
        );
        $checks[] = array(
            'label'  => 'REST API restricted',
            'status' => ! empty($h['disable_rest_anon']),
            'fix'    => 'Enable "Restrict REST API" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'Directory listing blocked',
            'status' => ! empty($h['disable_directory_listing']),
            'fix'    => 'Enable "Disable Directory Listing" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'Strong passwords enforced',
            'status' => ! empty($h['strong_passwords']),
            'fix'    => 'Enable "Strong Passwords" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'Author scan blocked',
            'status' => ! empty($h['disable_author_scan']),
            'fix'    => 'Enable "Block Author Scan" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'SSL active (HTTPS)',
            'status' => is_ssl(),
            'fix'    => 'Install an SSL certificate and enable HTTPS',
        );
        $checks[] = array(
            'label'  => 'WP debug off',
            'status' => ! ( defined('WP_DEBUG') && WP_DEBUG ),
            'fix'    => 'Set define(\'WP_DEBUG\', false); in wp-config.php',
        );
        $checks[] = array(
            'label'  => 'Admin username not "admin"',
            'status' => ! username_exists('admin'),
            'fix'    => 'Rename the "admin" user to something unique',
        );
        $checks[] = array(
            'label'  => 'Sensitive files blocked (.log/.bak/.sql/config backups)',
            'status' => ! empty($h['block_sensitive_files']),
            'fix'    => 'Enable "Block Sensitive Files" in Hardening settings',
        );
        $checks[] = array(
            'label'  => 'Debug log kept outside the webroot',
            'status' => ! ( defined('WP_DEBUG_LOG') && ( WP_DEBUG_LOG === true || ( is_string(WP_DEBUG_LOG) && strpos( WP_DEBUG_LOG, ABSPATH ) === 0 ) ) ),
            'fix'    => 'Set WP_DEBUG_LOG to an absolute path outside the webroot in wp-config.php',
        );
        return $checks;
    }
}
