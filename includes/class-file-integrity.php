<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_File_Integrity {

    const BASELINE_OPTION = 'swps_file_baseline';
    const LAST_SCAN_OPTION = 'swps_fim_last_scan';
    // Fallback location, used only if a webroot-external directory can't be created.
    const QUARANTINE_DIR_FALLBACK = WP_CONTENT_DIR . '/swps-quarantine/';

    /**
     * Quarantined files are moved here. Preferred location is OUTSIDE the
     * webroot (a sibling of ABSPATH) so quarantined malware/secrets have no
     * URL at all — this doesn't depend on the host actually honoring
     * .htaccess access-control directives (confirmed unreliable on at least
     * one OpenLiteSpeed setup). Falls back to a protected wp-content
     * subfolder only if the webroot-external path isn't writable.
     */
    public static function quarantine_dir() {
        static $dir = null;
        if ( $dir !== null ) return $dir;

        $outside = dirname( rtrim( ABSPATH, '/\\' ) ) . '/swps-quarantine/';
        if ( wp_mkdir_p( $outside ) && is_writable( $outside ) ) {
            $dir = $outside;
        } else {
            $dir = self::QUARANTINE_DIR_FALLBACK;
            if ( ! is_dir( $dir ) ) wp_mkdir_p( $dir );
        }
        return $dir;
    }

    public static function init() {
        add_action( 'swps_hourly_check', array( __CLASS__, 'run_check' ) );
        add_action( 'admin_init',        array( __CLASS__, 'maybe_auto_baseline' ) );
        add_action( 'wp_ajax_swps_fim_baseline',  array( __CLASS__, 'ajax_create_baseline' ) );
        add_action( 'wp_ajax_swps_fim_scan',      array( __CLASS__, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_swps_fim_restore',   array( __CLASS__, 'ajax_restore_file' ) );
        add_action( 'wp_ajax_swps_fim_ignore',    array( __CLASS__, 'ajax_ignore_file' ) );
    }

    /* ── Baseline ─────────────────────────────────────────────────────────── */

    public static function create_baseline() {
        $files    = self::get_monitored_files();
        $baseline = array();
        foreach ( $files as $path ) {
            if ( is_readable($path) ) {
                $baseline[ self::rel($path) ] = array(
                    'hash'  => hash_file( 'sha256', $path ),
                    'size'  => filesize($path),
                    'mtime' => filemtime($path),
                );
            }
        }
        update_option( self::BASELINE_OPTION, $baseline );
        update_option( 'swps_fim_baseline_created', time() );
        SWPS_Activity_Log::add( 'fim_baseline', 'info', 'File integrity baseline created — ' . count($baseline) . ' files hashed' );
        return count($baseline);
    }

    public static function ajax_create_baseline() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $count = self::create_baseline();
        wp_send_json_success( array( 'count' => $count, 'message' => "Baseline created with $count files." ) );
    }

    /**
     * Automatic baseline management (no manual step required):
     *  - First run: create an initial trusted baseline automatically.
     *  - On OUR OWN plugin update: refresh only our own files so a legit update
     *    doesn't spam "modified" warnings. Changes to any other file stay
     *    flagged — auto-trusting everything would defeat the purpose of FIM.
     */
    public static function maybe_auto_baseline() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['fim_enabled'] ) ) return;

        $baseline = get_option( self::BASELINE_OPTION, array() );

        if ( empty( $baseline ) ) {
            self::create_baseline();
            update_option( 'swps_fim_plugin_version', SWPS_VERSION );
            return;
        }

        if ( get_option( 'swps_fim_plugin_version' ) !== SWPS_VERSION ) {
            self::refresh_own_plugin_baseline();
            update_option( 'swps_fim_plugin_version', SWPS_VERSION );
        }
    }

    /**
     * Re-hash only this plugin's own files in the baseline (used after our own
     * legit update). Every other monitored file is left untouched.
     */
    public static function refresh_own_plugin_baseline() {
        $baseline   = get_option( self::BASELINE_OPTION, array() );
        $own_prefix = self::rel( SWPS_PLUGIN_DIR );

        foreach ( array_keys( $baseline ) as $rel ) {
            if ( strpos( $rel, $own_prefix ) === 0 ) unset( $baseline[ $rel ] );
        }
        foreach ( self::list_files( rtrim( SWPS_PLUGIN_DIR, '/\\' ), array('php','js','css') ) as $path ) {
            if ( ! is_readable( $path ) ) continue;
            $baseline[ self::rel( $path ) ] = array(
                'hash'  => hash_file( 'sha256', $path ),
                'size'  => filesize( $path ),
                'mtime' => filemtime( $path ),
            );
        }
        update_option( self::BASELINE_OPTION, $baseline );
    }

    /* ── Scan ─────────────────────────────────────────────────────────────── */

    public static function run_check() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['fim_enabled']) ) return;
        self::run_scan();
    }

    public static function run_scan() {
        $baseline = get_option( self::BASELINE_OPTION, array() );
        if ( empty($baseline) ) return array( 'error' => 'No baseline. Create baseline first.' );

        $ignored = get_option( 'swps_fim_ignored', array() );
        $files   = self::get_monitored_files();
        $changes = array();

        // Check for modified and new files
        foreach ( $files as $path ) {
            $rel = self::rel($path);
            if ( in_array($rel, $ignored) ) continue;
            if ( ! is_readable($path) ) continue;

            $hash = hash_file( 'sha256', $path );

            if ( ! isset($baseline[$rel]) ) {
                $changes[] = array( 'file' => $rel, 'type' => 'added', 'severity' => 'warning' );
            } elseif ( $hash !== $baseline[$rel]['hash'] ) {
                $changes[] = array(
                    'file'        => $rel,
                    'type'        => 'modified',
                    'severity'    => self::get_severity($rel),
                    'old_hash'    => $baseline[$rel]['hash'],
                    'new_hash'    => $hash,
                    'mtime'       => date_i18n( 'Y-m-d H:i:s', filemtime($path) ),
                );
            }
        }

        // Check for deleted files
        foreach ( $baseline as $rel => $data ) {
            if ( in_array($rel, $ignored) ) continue;
            $full = ABSPATH . $rel;
            if ( ! file_exists($full) ) {
                $changes[] = array( 'file' => $rel, 'type' => 'deleted', 'severity' => 'info' );
            }
        }

        $result = array(
            'scanned_at' => time(),
            'total'      => count($files),
            'changes'    => $changes,
            'critical'   => count( array_filter($changes, fn($c) => $c['severity'] === 'critical') ),
            'warnings'   => count( array_filter($changes, fn($c) => $c['severity'] === 'warning') ),
        );

        update_option( self::LAST_SCAN_OPTION, $result );

        if ( ! empty($changes) ) {
            $critical_count = $result['critical'];
            $severity = $critical_count > 0 ? 'critical' : 'warning';
            SWPS_Activity_Log::add( 'fim_change', $severity, count($changes) . ' file(s) changed since baseline' );

            if ( $critical_count > 0 ) {
                SWPS_Email_Alerts::send_alert(
                    'SecureWP Shield: Critical File Changes Detected',
                    "$critical_count critical file(s) changed on your site.\n\nThis may indicate a hack or malware injection.\n\nFiles:\n" .
                    implode("\n", array_map( fn($c) => "- [{$c['type']}] {$c['file']}", array_filter($changes, fn($c) => $c['severity']==='critical') ))
                );
                // Notify via webhooks too
                if ( class_exists('SWPS_Webhooks') ) {
                    SWPS_Webhooks::send( 'file_change', array( 'changes' => $changes, 'critical' => $critical_count ) );
                }
            }
        }

        return $result;
    }

    public static function ajax_run_scan() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        wp_send_json_success( self::run_scan() );
    }

    /* ── Quarantine / Restore ────────────────────────────────────────────── */

    public static function quarantine_file( $rel_path ) {
        $src  = ABSPATH . $rel_path;
        if ( ! file_exists($src) ) return false;

        $qdir = self::quarantine_dir();

        // Belt-and-braces web protection in case quarantine_dir() had to fall
        // back to an in-webroot path — .htaccess rules aren't honored on
        // every host (confirmed on at least one OpenLiteSpeed setup), so
        // these are best-effort, not the primary protection.
        $htaccess = $qdir . '.htaccess';
        if ( ! file_exists($htaccess) ) file_put_contents( $htaccess, "Order Allow,Deny\nDeny from all\nRequire all denied\n" );
        $index = $qdir . 'index.php';
        if ( ! file_exists($index) ) file_put_contents( $index, "<?php\n// Silence is golden.\nexit;\n" );

        $dest     = $qdir . basename($rel_path) . '_' . time() . '_' . wp_generate_password(8, false) . '.quarantine';
        $moved    = rename( $src, $dest );

        if ( $moved ) {
            $log = get_option( 'swps_quarantine_log', array() );
            $log[] = array( 'original' => $rel_path, 'quarantine' => $dest, 'time' => time() );
            update_option( 'swps_quarantine_log', $log );
            SWPS_Activity_Log::add( 'file_quarantined', 'critical', "File quarantined: $rel_path" );
        }
        return $moved;
    }

    public static function ajax_restore_file() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $quarantine_path = sanitize_text_field( $_POST['quarantine_path'] ?? '' );
        $original_path   = sanitize_text_field( $_POST['original_path'] ?? '' );

        if ( strpos($quarantine_path, self::quarantine_dir()) !== 0 ) {
            wp_send_json_error('Invalid path');
        }

        // Fix: path traversal check on destination — prevents writing outside webroot
        $original_path = ltrim( str_replace( '\\', '/', $original_path ), '/' );
        if ( strpos( $original_path, '..' ) !== false ) {
            wp_send_json_error('Invalid path');
        }
        $resolved        = realpath( ABSPATH ) . '/' . $original_path;
        $real_target_dir = realpath( dirname( $resolved ) );
        if ( $real_target_dir === false || strpos( $real_target_dir, realpath( ABSPATH ) ) !== 0 ) {
            wp_send_json_error('Invalid path');
        }

        if ( rename( $quarantine_path, $resolved ) ) {
            SWPS_Activity_Log::add( 'file_restored', 'warning', "File restored from quarantine: $original_path" );
            wp_send_json_success('File restored.');
        } else {
            wp_send_json_error('Restore failed.');
        }
    }

    public static function ajax_ignore_file() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $file    = sanitize_text_field( $_POST['file'] ?? '' );
        $ignored = get_option( 'swps_fim_ignored', array() );
        if ( ! in_array($file, $ignored) ) $ignored[] = $file;
        update_option( 'swps_fim_ignored', $ignored );
        wp_send_json_success('File ignored.');
    }

    /* ── Helpers ─────────────────────────────────────────────────────────── */

    private static function get_monitored_files() {
        $settings = get_option( 'swps_settings', array() );
        $paths    = array();

        // Always monitor core files
        if ( empty($settings['fim_skip_core']) ) {
            $paths = array_merge( $paths, self::list_files( ABSPATH . 'wp-admin', array('php') ) );
            $paths = array_merge( $paths, self::list_files( ABSPATH . 'wp-includes', array('php') ) );
            // Root PHP files
            foreach ( glob( ABSPATH . '*.php' ) ?: array() as $f ) $paths[] = $f;
        }

        // wp-content (plugins + themes + root)
        if ( empty($settings['fim_skip_content']) ) {
            $paths = array_merge( $paths, self::list_files( WP_CONTENT_DIR . '/plugins', array('php','js') ) );
            $paths = array_merge( $paths, self::list_files( WP_CONTENT_DIR . '/themes', array('php','js','css') ) );
        }

        return array_unique($paths);
    }

    private static function list_files( $dir, $exts = array('php'), $limit = 50000 ) {
        if ( ! is_dir($dir) ) return array();
        $files = array();
        try {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ( $iter as $file ) {
                if ( count($files) >= $limit ) break;
                if ( in_array( strtolower($file->getExtension()), $exts ) ) {
                    $files[] = $file->getPathname();
                }
            }
        } catch ( Exception $e ) {}
        return $files;
    }

    private static function rel( $path ) {
        return ltrim( str_replace( ABSPATH, '', $path ), '/' );
    }

    private static function get_severity( $rel ) {
        // Core files = critical, plugins/themes = warning
        if ( strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0 ) return 'critical';
        if ( in_array( $rel, array('wp-config.php','index.php','.htaccess') ) ) return 'critical';
        return 'warning';
    }

    /**
     * Finds stray sensitive files (backups, dumps, logs, config saves) sitting
     * directly in the webroot or wp-content root — these don't belong to any
     * WordPress/plugin/theme file set and commonly leak credentials or secrets
     * (e.g. wp-config.php.bak, debug.log) regardless of whether the host's
     * .htaccess actually blocks direct access to them.
     */
    public static function scan_risky_files() {
        $exts  = array('log','bak','backup','old','orig','save','swp','sql','env','ini','cfg','conf','dist','dump');
        $found = array();

        foreach ( array( ABSPATH, WP_CONTENT_DIR . '/' ) as $dir ) {
            $items = @scandir( $dir );
            if ( ! $items ) continue;
            foreach ( $items as $item ) {
                $path = $dir . $item;
                if ( ! is_file( $path ) ) continue;
                // Catch both "debug.log" and trailing-numbered backups like
                // "wp-config.php.bak2" (strip trailing digits before matching).
                $ext = strtolower( pathinfo( $item, PATHINFO_EXTENSION ) );
                $ext = preg_replace( '/\d+$/', '', $ext );
                if ( in_array( $ext, $exts, true ) ) {
                    $found[] = self::rel( $path );
                }
            }
        }
        return array_values( array_unique( $found ) );
    }

    public static function get_quarantine_log() {
        return get_option( 'swps_quarantine_log', array() );
    }

    public static function get_stats() {
        $last = get_option( self::LAST_SCAN_OPTION, array() );
        $baseline = get_option( self::BASELINE_OPTION, array() );
        return array(
            'baseline_files'    => count($baseline),
            'baseline_created'  => get_option('swps_fim_baseline_created', 0),
            'last_scan'         => $last['scanned_at'] ?? 0,
            'changes'           => $last['changes'] ?? array(),
            'critical_changes'  => $last['critical'] ?? 0,
        );
    }
}
