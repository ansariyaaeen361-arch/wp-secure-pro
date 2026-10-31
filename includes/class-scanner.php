<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Scanner {

    private static $suspicious_patterns = array(
        'eval\s*\(\s*base64_decode'      => 'Base64 encoded eval (common malware)',
        'eval\s*\(\s*gzinflate'          => 'Compressed eval (malware obfuscation)',
        'eval\s*\(\s*str_rot13'          => 'ROT13 eval (malware obfuscation)',
        'assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)' => 'Remote code execution via assert',
        'preg_replace\s*\(.*\/e[\'"]'    => 'preg_replace /e flag (code execution)',
        '\$GLOBALS\[.{0,20}\]\s*\(\s*\$_(POST|GET|REQUEST)' => 'Variable function call from input',
        'passthru\s*\(\s*\$_(POST|GET)'  => 'Shell passthru from user input',
        'shell_exec\s*\(\s*\$_(POST|GET)'=> 'shell_exec from user input',
        'system\s*\(\s*\$_(POST|GET)'    => 'system() from user input',
        'FilesMan'                        => 'Known webshell signature (FilesMan)',
        'c99shell'                        => 'Known webshell (c99)',
        'r57shell'                        => 'Known webshell (r57)',
        'WSO\s+Web\s+Shell'              => 'WSO webshell signature',
        'phpspy'                          => 'PHPSpy backdoor signature',
    );

    private static $scan_dirs = array(
        'wp-content/uploads',
        'wp-content/themes',
        'wp-content/plugins',
    );

    public static function run_scan() {
        $results = array(
            'total_files'   => 0,
            'scanned_files' => 0,
            'threats'       => array(),
            'scan_time'     => current_time('mysql'),
        );

        // WP_CONTENT_DIR already contains uploads/themes/plugins, so scan it
        // once to avoid scanning (and counting) the same files twice.
        $dirs = array();
        if ( is_dir( WP_CONTENT_DIR ) ) {
            $dirs[] = WP_CONTENT_DIR;
        } else {
            foreach ( self::$scan_dirs as $rel ) {
                $full = ABSPATH . $rel;
                if ( is_dir( $full ) ) $dirs[] = $full;
            }
        }

        $files = self::get_php_files( $dirs );
        $results['total_files'] = count( $files );

        foreach ( $files as $file ) {
            $results['scanned_files']++;
            $threats = self::scan_file( $file );
            if ( ! empty( $threats ) ) {
                $results['threats'][] = array(
                    'file'    => str_replace( ABSPATH, '', $file ),
                    'threats' => $threats,
                    'size'    => filesize( $file ),
                    'modified'=> date( 'Y-m-d H:i:s', filemtime( $file ) ),
                );
            }
        }

        // Log scan result
        $threat_count = count( $results['threats'] );
        SWPS_Activity_Log::add(
            'security_scan',
            $threat_count > 0 ? 'critical' : 'info',
            "Security scan completed: {$results['scanned_files']} files scanned, $threat_count threats found",
            array( 'threats' => $threat_count )
        );

        if ( $threat_count > 0 ) {
            $threat_list = '';
            foreach ( $results['threats'] as $t ) {
                $threat_list .= "\nFile: {$t['file']}\nIssues: " . implode(', ', $t['threats']) . "\n";
            }
            SWPS_Email_Alerts::send_alert(
                "MALWARE FOUND: $threat_count threats detected - " . get_bloginfo('name'),
                "Security scan found $threat_count suspicious files on your site.\n\n" .
                $threat_list .
                "\nPlease review these files immediately via:\n" . admin_url('admin.php?page=swps-scanner')
            );
        }

        update_option( 'swps_last_scan', $results, false );
        return $results;
    }

    /**
     * True for any file inside our own plugin. Its files reference malware
     * signature strings (in the engine and in the admin UI) and would self-flag.
     * The integrity of our own files is instead guarded by the File Integrity
     * Monitor (SHA-256 baseline), which detects any tampering here.
     */
    public static function is_own_plugin_file( $path ) {
        $norm = str_replace( '\\', '/', $path );
        $base = str_replace( '\\', '/', SWPS_PLUGIN_DIR );
        return strpos( $norm, $base ) === 0;
    }

    private static function get_php_files( $dirs ) {
        $files = array();
        foreach ( $dirs as $dir ) {
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ) );
            foreach ( $it as $file ) {
                if ( ! $file->isFile() ) continue;
                $path = $file->getPathname();
                // Skip our own plugin files (they reference signature strings).
                // Their integrity is covered by the FIM hash baseline instead.
                if ( self::is_own_plugin_file( $path ) ) continue;
                if ( in_array( strtolower( $file->getExtension() ), array('php','php5','php7','phtml') ) ) {
                    $files[] = $path;
                }
            }
        }
        return $files;
    }

    private static function scan_file( $file ) {
        $content = @file_get_contents( $file );
        if ( $content === false ) return array();
        return self::scan_content( $content );
    }

    /**
     * Runs the same signature set used for scheduled scans against raw
     * content. Exposed publicly so other modules (e.g. upload-time
     * scanning) can reuse the same detection logic instead of duplicating it.
     */
    public static function scan_content( $content ) {
        $threats = array();
        foreach ( self::$suspicious_patterns as $pattern => $label ) {
            if ( preg_match( '/' . $pattern . '/i', $content ) ) {
                $threats[] = $label;
            }
        }
        return $threats;
    }

    public static function get_last_scan() {
        return get_option( 'swps_last_scan', null );
    }

    public static function check_core_files() {
        $suspicious = array();
        $core_dirs  = array( ABSPATH . 'wp-admin', ABSPATH . 'wp-includes' );
        foreach ( $core_dirs as $dir ) {
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ) );
            foreach ( $it as $file ) {
                if ( $file->isFile() && strtolower($file->getExtension()) === 'php' ) {
                    $rel = str_replace( ABSPATH, '', $file->getPathname() );
                    // Flag any PHP file in core that was modified recently (last 7 days)
                    if ( $file->getMTime() > strtotime('-7 days') ) {
                        $suspicious[] = array( 'file' => $rel, 'modified' => date('Y-m-d H:i:s', $file->getMTime()) );
                    }
                }
            }
        }
        return $suspicious;
    }
}
