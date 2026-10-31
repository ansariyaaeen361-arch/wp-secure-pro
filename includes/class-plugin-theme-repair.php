<?php
if ( ! defined('ABSPATH') ) exit;

/**
 * "Auto Fix" for plugin/theme files — the same idea as SWPS_Core_Repair but
 * for wp-content/plugins and wp-content/themes, which that class can't
 * cover (WordPress.org's core checksums API only knows about core files).
 *
 * Honest limitation, matching what the research into Wordfence, Sucuri and
 * Solid Security found about ALL of them: this only works for plugins and
 * themes actually hosted on WordPress.org, since that's the only place with
 * a publicly fetchable "official" copy to restore from. A premium plugin
 * (Elementor Pro, Divi, a purchased theme) has no such public source — for
 * those, Quarantine (move the suspicious file aside) is the only safe
 * automated action; repairing it would mean trusting an unverifiable guess.
 */
class SWPS_Plugin_Theme_Repair {

    const PLUGIN_INFO_API = 'https://api.wordpress.org/plugins/info/1.0/%s.json';
    const THEME_INFO_API  = 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=%s';
    const PLUGIN_SVN      = 'https://plugins.svn.wordpress.org/%s/tags/%s/%s';
    const THEME_SVN       = 'https://themes.svn.wordpress.org/%s/%s/%s';

    public static function init() {
        add_action( 'wp_ajax_swps_repair_plugin_file', array( __CLASS__, 'ajax_repair_plugin_file' ) );
        add_action( 'wp_ajax_swps_repair_theme_file',  array( __CLASS__, 'ajax_repair_theme_file' ) );
    }

    /* ── Is this slug actually on WordPress.org? (cached) ── */
    public static function is_wporg_plugin( $slug ) {
        $key = 'swps_wporg_plugin_' . $slug;
        $cached = get_transient( $key );
        if ( $cached !== false ) return $cached === 'yes';

        $resp = wp_remote_get( sprintf( self::PLUGIN_INFO_API, $slug ), array( 'timeout' => 10 ) );
        $ok   = ! is_wp_error( $resp ) && wp_remote_retrieve_response_code( $resp ) === 200
                && strpos( wp_remote_retrieve_body( $resp ), '"error"' ) === false;

        set_transient( $key, $ok ? 'yes' : 'no', 7 * DAY_IN_SECONDS );
        return $ok;
    }

    public static function is_wporg_theme( $slug ) {
        $key = 'swps_wporg_theme_' . $slug;
        $cached = get_transient( $key );
        if ( $cached !== false ) return $cached === 'yes';

        $resp = wp_remote_get( sprintf( self::THEME_INFO_API, $slug ), array( 'timeout' => 10 ) );
        $ok   = ! is_wp_error( $resp ) && wp_remote_retrieve_response_code( $resp ) === 200
                && strpos( wp_remote_retrieve_body( $resp ), '"error"' ) === false;

        set_transient( $key, $ok ? 'yes' : 'no', 7 * DAY_IN_SECONDS );
        return $ok;
    }

    /** "wp-content/plugins/elementor/includes/foo.php" -> ['elementor', 'includes/foo.php'] */
    private static function split_plugin_path( $rel ) {
        if ( ! preg_match( '#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m ) ) return null;
        return array( $m[1], $m[2] );
    }

    private static function split_theme_path( $rel ) {
        if ( ! preg_match( '#^wp-content/themes/([^/]+)/(.+)$#', $rel, $m ) ) return null;
        return array( $m[1], $m[2] );
    }

    private static function installed_plugin_version( $slug ) {
        if ( ! function_exists('get_plugins') ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        foreach ( get_plugins() as $plugin_file => $data ) {
            if ( strpos( $plugin_file, $slug . '/' ) === 0 || $plugin_file === $slug . '.php' ) {
                return $data['Version'] ?? null;
            }
        }
        return null;
    }

    private static function installed_theme_version( $slug ) {
        $theme = wp_get_theme( $slug );
        return $theme->exists() ? $theme->get('Version') : null;
    }

    public static function repair_plugin_file( $rel_path ) {
        $rel_path = ltrim( str_replace('..', '', $rel_path), '/\\' );
        $parts    = self::split_plugin_path( $rel_path );
        if ( ! $parts ) return array( 'success' => false, 'message' => 'Not a plugin file.' );
        list( $slug, $inner ) = $parts;

        if ( ! self::is_wporg_plugin( $slug ) ) {
            return array( 'success' => false, 'message' => "\"$slug\" isn't on WordPress.org — no official copy exists to repair from. Use Quarantine instead." );
        }
        $version = self::installed_plugin_version( $slug );
        if ( ! $version ) return array( 'success' => false, 'message' => 'Could not determine installed plugin version.' );

        return self::download_and_replace( sprintf( self::PLUGIN_SVN, $slug, $version, $inner ), ABSPATH . $rel_path, $rel_path );
    }

    public static function repair_theme_file( $rel_path ) {
        $rel_path = ltrim( str_replace('..', '', $rel_path), '/\\' );
        $parts    = self::split_theme_path( $rel_path );
        if ( ! $parts ) return array( 'success' => false, 'message' => 'Not a theme file.' );
        list( $slug, $inner ) = $parts;

        if ( ! self::is_wporg_theme( $slug ) ) {
            return array( 'success' => false, 'message' => "\"$slug\" isn't on WordPress.org — no official copy exists to repair from. Use Quarantine instead." );
        }
        $version = self::installed_theme_version( $slug );
        if ( ! $version ) return array( 'success' => false, 'message' => 'Could not determine installed theme version.' );

        return self::download_and_replace( sprintf( self::THEME_SVN, $slug, $version, $inner ), ABSPATH . $rel_path, $rel_path );
    }

    private static function download_and_replace( $svn_url, $full_path, $rel_path ) {
        $resp = wp_remote_get( $svn_url, array( 'timeout' => 30 ) );
        if ( is_wp_error( $resp ) ) return array( 'success' => false, 'message' => $resp->get_error_message() );
        if ( wp_remote_retrieve_response_code( $resp ) !== 200 ) {
            return array( 'success' => false, 'message' => 'Official copy not found at that version (file may be new, or version mismatch).' );
        }

        $content = wp_remote_retrieve_body( $resp );
        $dir     = dirname( $full_path );
        if ( ! file_exists( $dir ) ) wp_mkdir_p( $dir );

        if ( file_exists( $full_path ) ) {
            copy( $full_path, $full_path . '.swps_bak_' . date('Ymd_His') );
        }
        if ( ! file_put_contents( $full_path, $content ) ) {
            return array( 'success' => false, 'message' => 'Could not write file — check permissions.' );
        }

        SWPS_Audit_Trail::log( 'plugin_theme_file_repaired', 'core', '', $rel_path, 'Restored from WordPress.org' );
        return array( 'success' => true, 'message' => "Repaired: $rel_path" );
    }

    public static function ajax_repair_plugin_file() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $result = self::repair_plugin_file( sanitize_text_field( $_POST['file'] ?? '' ) );
        $result['success'] ? wp_send_json_success( $result['message'] ) : wp_send_json_error( $result['message'] );
    }

    public static function ajax_repair_theme_file() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $result = self::repair_theme_file( sanitize_text_field( $_POST['file'] ?? '' ) );
        $result['success'] ? wp_send_json_success( $result['message'] ) : wp_send_json_error( $result['message'] );
    }
}
