<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_GitHub_Updater {

    /* ── CONFIG ── */
    const GITHUB_USER = 'ansariyaaeen361-arch';
    const GITHUB_REPO = 'wp-secure-pro';

    private static $plugin_file;   // "slug/main-file.php"
    private static $plugin_slug;   // "slug"
    private static $cache_key = 'swps_github_latest_release';

    public static function init() {
        self::$plugin_file = plugin_basename( SWPS_PLUGIN_DIR . 'wp-secure-pro.php' );
        self::$plugin_slug = dirname( self::$plugin_file );

        add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );
        add_filter( 'plugins_api',                           array( __CLASS__, 'plugin_info' ), 20, 3 );
        add_filter( 'upgrader_pre_download',                 array( __CLASS__, 'download_package' ), 10, 3 );
        add_filter( 'upgrader_source_selection',             array( __CLASS__, 'fix_folder_name' ), 10, 4 );
        add_action( 'upgrader_process_complete',             array( __CLASS__, 'clear_cache' ), 10, 0 );
        add_action( 'wp_ajax_swps_check_github_update',      array( __CLASS__, 'ajax_check_now' ) );

        // Fix: confirmed live — clicking "Check Again" on the WordPress
        // Updates page only clears WP's own update_plugins transient; our
        // separate 12-hour GitHub-release cache was untouched by that, so
        // a real new release could sit invisible for up to 12 hours even
        // after an explicit manual recheck. Clear ours too whenever the
        // admin explicitly asks WP to force a fresh check.
        add_action( 'load-update-core.php', array( __CLASS__, 'maybe_clear_cache_on_force_check' ) );
    }

    public static function maybe_clear_cache_on_force_check() {
        if ( ! empty( $_GET['force-check'] ) ) self::clear_cache();
    }

    public static function ajax_check_now() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error( 'Unauthorized' );

        self::clear_cache();
        $r = self::get_latest_release();
        if ( ! $r ) {
            wp_send_json_error( 'Could not reach GitHub (check the repo name/token, or that a release exists).' );
        }
        $new = self::latest_version( $r );
        delete_site_transient( 'update_plugins' ); // force WP to re-run check_for_update with fresh data
        if ( version_compare( $new, SWPS_VERSION, '>' ) ) {
            wp_send_json_success( "Update available: v{$new} (you're on v" . SWPS_VERSION . "). Go to Plugins to update." );
        }
        wp_send_json_success( "Already up to date (latest release: v{$new})." );
    }

    private static function api_args() {
        return array( 'timeout' => 20, 'headers' => array(
            'Accept'     => 'application/vnd.github+json',
            'User-Agent' => 'WP-Secure-Pro-Updater',
        ) );
    }

    private static function get_latest_release() {
        $cached = get_transient( self::$cache_key );
        if ( $cached !== false ) return $cached ?: null;

        $url  = sprintf( 'https://api.github.com/repos/%s/%s/releases/latest', self::GITHUB_USER, self::GITHUB_REPO );
        $resp = wp_remote_get( $url, self::api_args() );
        if ( is_wp_error( $resp ) || wp_remote_retrieve_response_code( $resp ) !== 200 ) {
            set_transient( self::$cache_key, '', HOUR_IN_SECONDS );
            return null;
        }
        $data = json_decode( wp_remote_retrieve_body( $resp ), true );
        if ( empty( $data['tag_name'] ) ) { set_transient( self::$cache_key, '', HOUR_IN_SECONDS ); return null; }

        set_transient( self::$cache_key, $data, 12 * HOUR_IN_SECONDS );
        return $data;
    }

    public static function clear_cache() { delete_transient( self::$cache_key ); }

    private static function latest_version( $r ) { return ltrim( $r['tag_name'], 'vV' ); }

    private static function asset_url( $r ) {
        if ( empty( $r['assets'] ) ) return null;
        foreach ( $r['assets'] as $a ) if ( substr( $a['name'], -4 ) === '.zip' ) return $a['url'];
        return null;
    }

    private static function signature_url( $r, $package_url ) {
        foreach ( (array) ( $r['assets'] ?? array() ) as $a ) {
            if ( ! empty( $a['url'] ) && $a['url'] === $package_url ) {
                $name = (string) ( $a['name'] ?? '' );
                foreach ( (array) ( $r['assets'] ?? array() ) as $candidate ) {
                    if ( (string) ( $candidate['name'] ?? '' ) === $name . '.sig' ) return $candidate['url'] ?? null;
                }
            }
        }
        return null;
    }

    private static function public_key() {
        if ( ! defined( 'SWPS_UPDATE_PUBLIC_KEY' ) || ! SWPS_UPDATE_PUBLIC_KEY || ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) return null;
        $key = base64_decode( (string) SWPS_UPDATE_PUBLIC_KEY, true );
        return $key !== false && strlen( $key ) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? $key : null;
    }

    private static function update_is_verifiable( $r, $package_url ) {
        return self::public_key() && self::signature_url( $r, $package_url );
    }

    public static function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;
        $r = self::get_latest_release();
        if ( ! $r ) return $transient;

        $new = self::latest_version( $r );
        if ( version_compare( $new, SWPS_VERSION, '>' ) ) {
            $pkg = self::asset_url( $r );
            if ( ! $pkg || ! self::update_is_verifiable( $r, $pkg ) ) return $transient;
            $transient->response[ self::$plugin_file ] = (object) array(
                'slug' => self::$plugin_slug, 'plugin' => self::$plugin_file,
                'new_version' => $new, 'url' => $r['html_url'] ?? '',
                'package' => $pkg, 'tested' => get_bloginfo( 'version' ),
            );
        } else {
            $transient->no_update[ self::$plugin_file ] = (object) array(
                'slug' => self::$plugin_slug, 'plugin' => self::$plugin_file,
                'new_version' => SWPS_VERSION, 'package' => '',
            );
        }
        return $transient;
    }

    public static function plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) return $result;
        if ( empty( $args->slug ) || $args->slug !== self::$plugin_slug ) return $result;
        $r = self::get_latest_release();
        if ( ! $r ) return $result;
        return (object) array(
            'name' => 'WP Secure Pro', 'slug' => self::$plugin_slug, 'author' => SWPS_AUTHOR,
            'version' => self::latest_version( $r ), 'homepage' => $r['html_url'] ?? '',
            'download_link' => self::asset_url( $r ), 'last_updated' => $r['published_at'] ?? '',
            'sections' => array( 'changelog' => wpautop( esc_html( $r['body'] ?? '' ) ) ),
        );
    }

    public static function download_package( $reply, $package, $upgrader ) {
        if ( strpos( (string) $package, 'api.github.com/repos/' . self::GITHUB_USER . '/' . self::GITHUB_REPO ) === false ) return $reply;
        $release = self::get_latest_release();
        $sig_url = $release ? self::signature_url( $release, $package ) : null;
        $public_key = self::public_key();
        if ( ! $sig_url || ! $public_key ) return new WP_Error( 'swps_unsigned_update', 'Update rejected: a valid Ed25519 signing key and detached .sig release asset are required.' );

        $args = array( 'timeout' => 300, 'headers' => array(
            'Accept' => 'application/octet-stream', 'User-Agent' => 'WP-Secure-Pro-Updater' ) );

        $resp = wp_remote_get( $package, $args );
        if ( is_wp_error( $resp ) ) return $resp;
        if ( wp_remote_retrieve_response_code( $resp ) !== 200 ) return new WP_Error( 'dl', 'GitHub asset download failed (token/permission?).' );
        $body = wp_remote_retrieve_body( $resp );
        $sig_response = wp_remote_get( $sig_url, $args );
        if ( is_wp_error( $sig_response ) || wp_remote_retrieve_response_code( $sig_response ) !== 200 ) return new WP_Error( 'sig', 'Update rejected: signature download failed.' );
        $signature = wp_remote_retrieve_body( $sig_response );
        $decoded = base64_decode( trim( $signature ), true );
        if ( $decoded !== false ) $signature = $decoded;
        if ( ! sodium_crypto_sign_verify_detached( $signature, $body, $public_key ) ) return new WP_Error( 'sig', 'Update rejected: Ed25519 signature verification failed.' );

        $tmp = wp_tempnam( 'plugin-update.zip' );
        if ( ! $tmp ) return new WP_Error( 'tmp', 'Temp file fail.' );
        file_put_contents( $tmp, $body, LOCK_EX );
        return $tmp;
    }

    public static function fix_folder_name( $source, $remote_source, $upgrader, $hook_extra = array() ) {
        global $wp_filesystem;
        if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== self::$plugin_file ) return $source;
        $desired = trailingslashit( $remote_source ) . self::$plugin_slug . '/';
        if ( trailingslashit( $source ) === $desired ) return $source;
        return $wp_filesystem->move( $source, $desired, true ) ? $desired : $source;
    }
}
