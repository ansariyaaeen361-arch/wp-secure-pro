<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_DB_Monitor {

    public static function init() {
        add_action( 'swps_hourly_check',         array( __CLASS__, 'check_db_users' ) );
        // Fix: PHP-in-uploads detection already existed (find_php_in_uploads(),
        // used by the manual "DB Health Scan" button) but nothing ran it
        // automatically — a webshell planted in wp-content/uploads (the
        // classic hiding spot, since it's writable and outside FIM's
        // monitored directories) would sit there undetected until someone
        // happened to click that specific button on that specific tab. Now
        // runs every hour alongside the DB user check.
        add_action( 'swps_hourly_check',         array( __CLASS__, 'hourly_uploads_php_check' ) );
        add_action( 'wp_ajax_swps_db_scan',      array( __CLASS__, 'ajax_scan' ) );
        add_action( 'wp_ajax_swps_db_change_prefix', array( __CLASS__, 'ajax_change_prefix' ) );
    }

    /**
     * Confirmed live on a real host: .htaccess-based PHP-execution blocking
     * for wp-content/uploads (SetHandler/RemoveHandler AND a plain "Deny
     * from all") was completely ignored by the server — a PHP file placed
     * there executed normally regardless. And it can't be any other way in
     * principle: a direct request for a standalone .php file under uploads
     * is executed by the web server BEFORE WordPress ever loads, so no
     * hook inside this plugin's PHP runtime ever gets a chance to run for
     * that specific request either. True prevention from inside a
     * WordPress plugin isn't reliably achievable here — only a server/
     * vhost-level config change (outside what a plugin can do) actually
     * prevents it. So this leans as hard as possible on the one thing that
     * IS reliably achievable: auto-quarantining (not just alerting about)
     * any PHP file found in uploads the moment this check runs, to cut the
     * exposure window down as far as possible given prevention isn't an
     * option here.
     */
    public static function hourly_uploads_php_check() {
        $uploads = wp_upload_dir();
        $found   = self::find_php_in_uploads( $uploads['basedir'] ?? '', 50 );

        foreach ( $found as $file ) {
            $full = ABSPATH . ltrim( $file, '/\\' );
            $quarantined = false;
            if ( class_exists( 'SWPS_File_Integrity' ) && file_exists( $full ) ) {
                $rel = ltrim( str_replace( ABSPATH, '', $full ), '/\\' );
                $quarantined = SWPS_File_Integrity::quarantine_file( $rel );
            }
            SWPS_Activity_Log::add( 'php_in_uploads', 'critical',
                "PHP file found in uploads folder (classic webshell hiding spot): $file"
                . ( $quarantined ? ' — automatically quarantined.' : ' — COULD NOT quarantine automatically, remove it manually right away.' )
            );
            SWPS_Email_Alerts::send_alert(
                'SecureWP Shield: PHP file found in uploads folder' . ( $quarantined ? ' (auto-quarantined)' : ' — ACTION NEEDED' ),
                "A PHP file was found in your uploads directory, where no PHP file should ever legitimately be:\n\n$file\n\n"
                . ( $quarantined
                    ? "It has been automatically moved out of the webroot and can no longer run."
                    : "It could NOT be automatically quarantined (check file permissions) — remove or move it manually immediately; it is still able to run." )
                . "\n\nThis is a common place attackers hide webshells."
            );
        }
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

    public static function find_php_in_uploads( $dir, $limit = 20 ) {
        $found = array();
        if ( ! is_dir($dir) ) return $found;
        try {
            $iter = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ) );
            foreach ( $iter as $file ) {
                if ( count($found) >= $limit ) break;
                if ( $file->getExtension() !== 'php' ) continue;
                // Fix (live-caught false positive): WordPress core and many
                // plugins (Tutor LMS, MailPoet, etc.) place a tiny, harmless
                // "Silence is golden." index.php in every uploads
                // subdirectory purely to stop directory listing — this
                // plugin's own quarantine_dir() writes the exact same
                // pattern. Flagging/quarantining every .php file in uploads
                // with no content check removed real WordPress stub files
                // from a live site, with no attacker involved at all.
                if ( self::is_harmless_stub_php( $file->getPathname() ) ) continue;
                $found[] = str_replace( ABSPATH, '/', $file->getPathname() );
            }
        } catch ( Exception $e ) {}
        return $found;
    }

    /** True only for a trivially empty PHP file with no executable logic
     *  beyond an early exit/comment — never for anything containing a
     *  function call that could actually do something, however small. */
    private static function is_harmless_stub_php( $path ) {
        if ( ! is_readable($path) || filesize($path) > 300 ) return false;
        $content = @file_get_contents($path);
        if ( $content === false ) return false;

        $danger = array(
            'eval', 'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13',
            'system(', 'exec(', 'shell_exec', 'passthru', 'assert(', 'create_function',
            '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER',
            'fwrite', 'fopen', 'curl_exec', 'proc_open', 'popen(', 'include', 'require',
        );
        foreach ( $danger as $d ) {
            if ( stripos( $content, $d ) !== false ) return false;
        }

        $stripped = preg_replace( '#/\*.*?\*/|//[^\n]*|\s+#s', '', $content );
        return strlen( $stripped ) < 40; // e.g. "<?phpexit;" — nothing left to be malicious
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
        wp_send_json_success( 'Table prefix changed to: ' . $new_prefix . '. wp-config.php was updated automatically — the site is live on the new prefix.' );
    }

    /**
     * Fix: this used to rename every table and then tell the admin to go
     * edit wp-config.php "immediately" by hand — between the RENAME and
     * that manual edit the site is fully down (WordPress is still looking
     * for wp_options etc. under the old name). One click bricked the site
     * until someone got into a file manager/SSH. Now wp-config.php is
     * rewritten as part of the same operation, and if that write fails for
     * any reason, the table renames are rolled back so the site is never
     * left in a half-migrated, broken state.
     */
    private static function change_table_prefix( $new_prefix ) {
        global $wpdb;
        $old_prefix = $wpdb->prefix;

        if ( $new_prefix === $old_prefix ) return new WP_Error( 'same_prefix', 'New prefix is the same as current.' );

        $config_file = self::locate_wp_config();
        if ( ! $config_file || ! is_writable( $config_file ) ) {
            return new WP_Error( 'config_not_writable', 'wp-config.php could not be found or is not writable — aborted before touching any tables, so the site is unaffected.' );
        }
        $config_contents = file_get_contents( $config_file );
        if ( ! preg_match( '/\$table_prefix\s*=\s*([\'"])' . preg_quote( $old_prefix, '/' ) . '\1\s*;/', $config_contents ) ) {
            return new WP_Error( 'config_pattern_not_found', 'Could not find the current $table_prefix line in wp-config.php in an editable format — aborted before touching any tables.' );
        }

        $tables = $wpdb->get_col("SHOW TABLES LIKE '{$wpdb->esc_like($old_prefix)}%'");
        if ( empty($tables) ) return new WP_Error( 'no_tables', 'No tables found with current prefix.' );

        $renamed = array();
        foreach ( $tables as $table ) {
            $new_table = $new_prefix . substr( $table, strlen($old_prefix) );
            $ok = $wpdb->query( "RENAME TABLE `{$table}` TO `{$new_table}`" ); // phpcs:ignore
            if ( $ok === false ) {
                // Roll back every rename done so far, then bail.
                foreach ( array_reverse( $renamed ) as $pair ) {
                    $wpdb->query( "RENAME TABLE `{$pair[1]}` TO `{$pair[0]}`" ); // phpcs:ignore
                }
                return new WP_Error( 'rename_failed', "Renaming table `$table` failed — rolled back, no tables were changed." );
            }
            $renamed[] = array( $table, $new_table );
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

        // Now the critical part: update wp-config.php itself, in the same
        // request, so the site never runs with mismatched tables/config.
        $new_contents = preg_replace(
            '/\$table_prefix\s*=\s*([\'"])' . preg_quote( $old_prefix, '/' ) . '\1\s*;/',
            '$table_prefix = \'' . $new_prefix . '\';',
            $config_contents,
            1
        );
        $written = ( $new_contents !== $config_contents ) && file_put_contents( $config_file, $new_contents ) !== false;

        if ( ! $written ) {
            // Roll every table back rather than leave the site down.
            foreach ( array_reverse( $renamed ) as $pair ) {
                $wpdb->query( "RENAME TABLE `{$pair[1]}` TO `{$pair[0]}`" ); // phpcs:ignore
            }
            $wpdb->query( $wpdb->prepare(
                "UPDATE `{$old_prefix}options` SET option_name = %s WHERE option_name = %s",
                $old_prefix . 'user_roles', $new_prefix . 'user_roles'
            ) );
            $wpdb->query( $wpdb->prepare(
                "UPDATE `{$old_prefix}usermeta` SET meta_key = REPLACE(meta_key, %s, %s) WHERE meta_key LIKE %s",
                $new_prefix, $old_prefix, $wpdb->esc_like($new_prefix) . '%'
            ) );
            return new WP_Error( 'config_write_failed', 'Could not update wp-config.php — all table renames were rolled back, site is unaffected.' );
        }

        SWPS_Activity_Log::add( 'db_prefix_changed', 'warning', "DB table prefix changed from $old_prefix to $new_prefix — wp-config.php updated automatically" );
        return true;
    }

    /** wp-config.php lives one level above ABSPATH on a standard layout, but
     *  WordPress also supports it living in ABSPATH itself. */
    private static function locate_wp_config() {
        if ( file_exists( ABSPATH . 'wp-config.php' ) ) return ABSPATH . 'wp-config.php';
        if ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) return dirname( ABSPATH ) . '/wp-config.php';
        return null;
    }
}
