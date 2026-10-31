<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_DB_Monitor {

    public static function init() {
        add_action( 'swps_hourly_check',         array( __CLASS__, 'check_db_users' ) );
        add_action( 'wp_ajax_swps_db_scan',      array( __CLASS__, 'ajax_scan' ) );
        add_action( 'wp_ajax_swps_db_change_prefix', array( __CLASS__, 'ajax_change_prefix' ) );
    }

    /* ---- Database User Audit ---- */

    public static function get_db_users() {
        global $wpdb;
        $users = $wpdb->get_results( "SELECT User, Host FROM mysql.user ORDER BY User", ARRAY_A );
        return $users ?: array();
    }

    public static function get_known_db_users() {
        return get_option( 'swps_known_db_users', array() );
    }

    public static function save_known_db_users( $users ) {
        update_option( 'swps_known_db_users', $users );
    }

    public static function check_db_users() {
        $current = self::get_db_users();
        if ( empty($current) ) return; // No SELECT on mysql.user — skip

        $known    = self::get_known_db_users();
        $cur_list = array_map( fn($u) => $u['User'] . '@' . $u['Host'], $current );

        if ( empty($known) ) {
            self::save_known_db_users( $cur_list );
            return;
        }

        $new_users = array_diff( $cur_list, $known );
        foreach ( $new_users as $user ) {
            SWPS_Activity_Log::add( 'rogue_db_user', 'critical', "Unknown MySQL user detected: $user" );
            SWPS_Email_Alerts::send_alert(
                'SecureWP Shield: Unknown Database User Detected',
                "A new MySQL user was detected: $user\n\nThis may indicate a database compromise. Please investigate immediately."
            );
        }
    }

    /* ---- Database Health Scan ---- */

    public static function ajax_scan() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        wp_send_json_success( self::run_scan() );
    }

    public static function run_scan() {
        global $wpdb;

        $results = array();

        // 1. Check table prefix (not default 'wp_')
        $prefix  = $wpdb->prefix;
        $results['prefix'] = array(
            'label'  => 'Table prefix',
            'value'  => $prefix,
            'status' => ( $prefix === 'wp_' ) ? 'warning' : 'ok',
            'note'   => ( $prefix === 'wp_' ) ? 'Default prefix — predictable, change it' : 'Custom prefix — good',
        );

        // 2. Check for extra admin users in wp_users
        $admins = get_users( array( 'role' => 'administrator' ) );
        $known  = get_option( 'swps_known_admins', array() );
        $rogue  = array_filter( $admins, fn($u) => ! in_array( $u->ID, $known ) );
        $results['admins'] = array(
            'label'  => 'Admin users',
            'value'  => count($admins),
            'status' => count($rogue) > 0 ? 'critical' : 'ok',
            'note'   => count($rogue) > 0 ? count($rogue) . ' unknown admin(s) found' : 'All admins are known',
        );

        // 3. Check for suspicious options (known malware stores payloads here)
        $bad_options = $wpdb->get_results(
            "SELECT option_name, CHAR_LENGTH(option_value) as len FROM {$wpdb->options}
             WHERE option_value LIKE '%eval(base64%' OR option_value LIKE '%shell_exec%'
             OR option_value LIKE '%system(%' OR option_value LIKE '%passthru(%'
             LIMIT 20",
            ARRAY_A
        );
        $results['bad_options'] = array(
            'label'  => 'Suspicious options',
            'value'  => count($bad_options),
            'status' => count($bad_options) > 0 ? 'critical' : 'ok',
            'note'   => count($bad_options) > 0 ? 'Malicious code found in options table' : 'Options table clean',
            'items'  => array_column( $bad_options, 'option_name' ),
        );

        // 4. Check for suspicious scheduled events (cron backdoors)
        $crons    = _get_cron_array();
        $bad_hooks = array();
        if ( is_array($crons) ) {
            foreach ( $crons as $timestamp => $hooks ) {
                foreach ( $hooks as $hook => $events ) {
                    if ( preg_match('/[a-z0-9]{12,}/', $hook) && ! str_contains( $hook, '_' ) ) {
                        $bad_hooks[] = $hook;
                    }
                }
            }
        }
        $results['cron'] = array(
            'label'  => 'Suspicious cron events',
            'value'  => count($bad_hooks),
            'status' => count($bad_hooks) > 0 ? 'warning' : 'ok',
            'note'   => count($bad_hooks) > 0 ? 'Unusual cron hooks detected' : 'Cron events look normal',
            'items'  => $bad_hooks,
        );

        // 5. Check DB user permissions (if accessible)
        $db_users = self::get_db_users();
        $results['db_users'] = array(
            'label'  => 'MySQL users',
            'value'  => count($db_users),
            'status' => 'ok',
            'note'   => count($db_users) > 0 ? count($db_users) . ' MySQL users found' : 'Cannot read mysql.user (permission denied)',
            'items'  => array_map( fn($u) => $u['User'] . '@' . $u['Host'], $db_users ),
        );

        // 6. Check for unauthorized file in uploads (PHP in uploads)
        $uploads     = wp_upload_dir();
        $php_uploads = self::find_php_in_uploads( $uploads['basedir'] );
        $results['php_uploads'] = array(
            'label'  => 'PHP files in uploads',
            'value'  => count($php_uploads),
            'status' => count($php_uploads) > 0 ? 'critical' : 'ok',
            'note'   => count($php_uploads) > 0 ? 'PHP files found in uploads folder (webshells?)' : 'No PHP files in uploads',
            'items'  => $php_uploads,
        );

        update_option( 'swps_last_db_scan', array( 'time' => time(), 'results' => $results ) );
        return $results;
    }

    private static function find_php_in_uploads( $dir, $limit = 20 ) {
        $found = array();
        if ( ! is_dir($dir) || count($found) >= $limit ) return $found;
        try {
            $iter = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ) );
            foreach ( $iter as $file ) {
                if ( $file->getExtension() === 'php' ) {
                    $found[] = str_replace( ABSPATH, '/', $file->getPathname() );
                    if ( count($found) >= $limit ) break;
                }
            }
        } catch ( Exception $e ) {}
        return $found;
    }

    /* ---- Table Prefix Changer ---- */

    public static function ajax_change_prefix() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $new_prefix = sanitize_text_field( $_POST['new_prefix'] ?? '' );
        if ( ! preg_match('/^[a-z][a-z0-9_]*_$/', $new_prefix ) ) {
            wp_send_json_error( 'Invalid prefix. Use only lowercase letters, numbers, underscores. Must end with underscore.' );
        }

        $result = self::change_table_prefix( $new_prefix );
        if ( is_wp_error($result) ) {
            wp_send_json_error( $result->get_error_message() );
        }
        wp_send_json_success( 'Table prefix changed to: ' . $new_prefix . '. Update wp-config.php manually.' );
    }

    private static function change_table_prefix( $new_prefix ) {
        global $wpdb;
        $old_prefix = $wpdb->prefix;

        if ( $new_prefix === $old_prefix ) return new WP_Error( 'same_prefix', 'New prefix is the same as current.' );

        $tables = $wpdb->get_col("SHOW TABLES LIKE '{$wpdb->esc_like($old_prefix)}%'");
        if ( empty($tables) ) return new WP_Error( 'no_tables', 'No tables found with current prefix.' );

        foreach ( $tables as $table ) {
            $new_table = $new_prefix . substr( $table, strlen($old_prefix) );
            $wpdb->query( "RENAME TABLE `{$table}` TO `{$new_table}`" ); // phpcs:ignore
        }

        // Update user and usermeta option names
        $wpdb->query( $wpdb->prepare(
            "UPDATE `{$new_prefix}options` SET option_name = %s WHERE option_name = %s",
            $new_prefix . 'user_roles', $old_prefix . 'user_roles'
        ) );
        $wpdb->query( $wpdb->prepare(
            "UPDATE `{$new_prefix}usermeta` SET meta_key = REPLACE(meta_key, %s, %s) WHERE meta_key LIKE %s",
            $old_prefix, $new_prefix, $wpdb->esc_like($old_prefix) . '%'
        ) );

        SWPS_Activity_Log::add( 'db_prefix_changed', 'warning', "DB table prefix changed from $old_prefix to $new_prefix — update wp-config.php" );
        return true;
    }
}
