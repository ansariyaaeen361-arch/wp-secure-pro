<?php
/**
 * Self-hosted update checker for SecureWP Shield via a PRIVATE GitHub repo.
 *
 * Jab aap GitHub par ek naya Release (tag) banate ho aur uske saath ek zip
 * asset attach karte ho (jisme top folder "securewp-shield/" ho), to client
 * sites ke dashboard me normal "Update available" notice aa jaayega. Update
 * ek click se lagega (manual mode) — token ke zariye private zip securely
 * download hoti hai.
 *
 * SETUP (3 cheezein bharni hain, neeche constants me):
 *   - GITHUB_USER : aapka GitHub username/org
 *   - GITHUB_REPO : repo ka naam
 *   - token       : wp-config.php me  define('SWPS_GITHUB_TOKEN', 'ghp_xxx');
 *                   ya Settings me save karke option 'swps_github_token'.
 *                   Fine-grained / read-only "Contents: Read" token kaafi hai.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_GitHub_Updater {

    /* ── CONFIG — yahan apni details bharein ──────────────────────────── */
    const GITHUB_USER = 'ansariyaaeen361-arch';
    const GITHUB_REPO = 'securewp-shield';

    // Baked-in READ-ONLY token (sirf is repo ko Contents:Read deta hai).
    // Yahan token daal do -> har release/site par khud chala jayega,
    // kisi site ke wp-config me manually daalne ki zaroorat NAHI.
    // (wp-config ka SWPS_GITHUB_TOKEN constant isko override kar sakta hai.)
    const BAKED_TOKEN = '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';
    /* ─────────────────────────────────────────────────────────────────── */
    /* ─────────────────────────────────────────────────────────────────── */

    private static $plugin_file;   // "securewp-shield/securewp-shield.php"
    private static $plugin_slug;   // "securewp-shield"
    private static $cache_key = 'swps_github_latest_release';

    public static function init() {
        self::$plugin_file = plugin_basename( SWPS_PLUGIN_DIR . 'securewp-shield.php' );
        self::$plugin_slug = dirname( self::$plugin_file );

        add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );
        add_filter( 'plugins_api',                           array( __CLASS__, 'plugin_info' ), 20, 3 );
        add_filter( 'upgrader_pre_download',                 array( __CLASS__, 'download_package' ), 10, 3 );
        add_filter( 'upgrader_source_selection',             array( __CLASS__, 'fix_folder_name' ), 10, 4 );

        // "Check again" ke baad fresh data mile iske liye cache clear.
        add_action( 'upgrader_process_complete', array( __CLASS__, 'clear_cache' ), 10, 0 );
    }

    /* ── GitHub token (constant pehle, phir option) ───────────────────── */
    private static function token() {
        if ( defined( 'SWPS_GITHUB_TOKEN' ) && SWPS_GITHUB_TOKEN ) return SWPS_GITHUB_TOKEN; // wp-config override
        $opt = trim( (string) get_option( 'swps_github_token', '' ) );                       // admin setting
        if ( $opt ) return $opt;
        return self::BAKED_TOKEN;                                                             // baked default
    }

    private static function api_args() {
        $headers = array(
            'Accept'     => 'application/vnd.github+json',
            'User-Agent' => 'SecureWP-Shield-Updater',
        );
        $token = self::token();
        if ( $token ) $headers['Authorization'] = 'Bearer ' . $token;
        return array( 'timeout' => 20, 'headers' => $headers );
    }

    /* ── Latest release GitHub se (12h cache) ─────────────────────────── */
    private static function get_latest_release() {
        $cached = get_transient( self::$cache_key );
        if ( $cached !== false ) return $cached ?: null;

        $url  = sprintf( 'https://api.github.com/repos/%s/%s/releases/latest',
                         self::GITHUB_USER, self::GITHUB_REPO );
        $resp = wp_remote_get( $url, self::api_args() );

        if ( is_wp_error( $resp ) || wp_remote_retrieve_response_code( $resp ) !== 200 ) {
            set_transient( self::$cache_key, '', HOUR_IN_SECONDS ); // short negative cache
            return null;
        }

        $data = json_decode( wp_remote_retrieve_body( $resp ), true );
        if ( empty( $data['tag_name'] ) ) {
            set_transient( self::$cache_key, '', HOUR_IN_SECONDS );
            return null;
        }

        set_transient( self::$cache_key, $data, 12 * HOUR_IN_SECONDS );
        return $data;
    }

    public static function clear_cache() {
        delete_transient( self::$cache_key );
    }

    private static function latest_version( $release ) {
        return ltrim( $release['tag_name'], 'vV' ); // "v5.1.0" -> "5.1.0"
    }

    /**
     * Release ke attached zip asset ka API URL (private download ke liye).
     * Agar koi asset attach nahi — null (zipball private pe reliable nahi).
     */
    private static function asset_url( $release ) {
        if ( empty( $release['assets'] ) ) return null;
        foreach ( $release['assets'] as $asset ) {
            if ( substr( $asset['name'], -4 ) === '.zip' ) {
                return $asset['url']; // .../releases/assets/{id}
            }
        }
        return null;
    }

    /* ── WordPress ko batao ke update available hai ───────────────────── */
    public static function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;

        $release = self::get_latest_release();
        if ( ! $release ) return $transient;

        $new_version = self::latest_version( $release );
        $current     = SWPS_VERSION;

        if ( version_compare( $new_version, $current, '>' ) ) {
            $package = self::asset_url( $release );
            if ( ! $package ) return $transient; // bina asset ke kuch na karo

            $transient->response[ self::$plugin_file ] = (object) array(
                'slug'        => self::$plugin_slug,
                'plugin'      => self::$plugin_file,
                'new_version' => $new_version,
                'url'         => $release['html_url'] ?? '',
                'package'     => $package,   // asset API url — niche auth se download hoga
                'tested'      => get_bloginfo( 'version' ),
            );
        } else {
            unset( $transient->response[ self::$plugin_file ] );
            $transient->no_update[ self::$plugin_file ] = (object) array(
                'slug'        => self::$plugin_slug,
                'plugin'      => self::$plugin_file,
                'new_version' => $current,
                'package'     => '',
            );
        }
        return $transient;
    }

    /* ── "View details" popup ─────────────────────────────────────────── */
    public static function plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) return $result;
        if ( empty( $args->slug ) || $args->slug !== self::$plugin_slug ) return $result;

        $release = self::get_latest_release();
        if ( ! $release ) return $result;

        return (object) array(
            'name'          => 'SecureWP Shield',
            'slug'          => self::$plugin_slug,
            'version'       => self::latest_version( $release ),
            'author'        => SWPS_AUTHOR,
            'homepage'      => $release['html_url'] ?? '',
            'download_link' => self::asset_url( $release ),
            'last_updated'  => $release['published_at'] ?? '',
            'sections'      => array(
                'changelog' => wpautop( esc_html( $release['body'] ?? 'No changelog provided.' ) ),
            ),
        );
    }

    /**
     * Private repo ka asset download() se nahi milta (auth chahiye).
     * Isliye hum khud token ke saath download karke temp file lauta dete hain.
     */
    public static function download_package( $reply, $package, $upgrader ) {
        // Sirf apne GitHub asset URLs handle karo
        if ( strpos( (string) $package, 'api.github.com/repos/' . self::GITHUB_USER . '/' . self::GITHUB_REPO ) === false ) {
            return $reply; // dusre plugins ke downloads ko haath mat lagao
        }

        $args = array(
            'timeout' => 300,
            'headers' => array(
                'Accept'     => 'application/octet-stream', // asset ki raw bytes
                'User-Agent' => 'SecureWP-Shield-Updater',
            ),
        );
        $token = self::token();
        if ( $token ) $args['headers']['Authorization'] = 'Bearer ' . $token;

        $tmp = download_url( $package, 300, false );
        // download_url auth headers nahi lagata, isliye manually fetch + save:
        if ( is_wp_error( $tmp ) ) {
            $resp = wp_remote_get( $package, $args );
            if ( is_wp_error( $resp ) )                              return $resp;
            if ( wp_remote_retrieve_response_code( $resp ) !== 200 ) return new WP_Error( 'swps_dl', 'GitHub asset download failed (check token/permissions).' );
            $body = wp_remote_retrieve_body( $resp );
            $tmp  = wp_tempnam( 'swps-update.zip' );
            if ( ! $tmp ) return new WP_Error( 'swps_tmp', 'Could not create temp file.' );
            file_put_contents( $tmp, $body );
        }
        return $tmp;
    }

    /**
     * GitHub zip ke andar jo bhi top folder ho, use plugin slug me rename
     * karo taake plugin ka folder change na ho (settings/activation bachein).
     */
    public static function fix_folder_name( $source, $remote_source, $upgrader, $hook_extra = array() ) {
        global $wp_filesystem;
        if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== self::$plugin_file ) {
            return $source;
        }
        $desired = trailingslashit( $remote_source ) . self::$plugin_slug . '/';
        if ( trailingslashit( $source ) === $desired ) return $source;

        if ( $wp_filesystem->move( $source, $desired, true ) ) return $desired;
        return $source;
    }
}
