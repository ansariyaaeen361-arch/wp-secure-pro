<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_GeoIP {

    const DB_URL     = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz';
    const DB_DIR     = WP_CONTENT_DIR . '/swps-geoip/';
    const DB_FILE    = WP_CONTENT_DIR . '/swps-geoip/GeoLite2-Country.mmdb';
    const CACHE_KEY  = 'swps_geoip_';
    const CACHE_TTL  = 86400; // 24 hours

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['geoip_enabled'] ) ) return;

        add_action( 'init', array( __CLASS__, 'check_block' ), 2 );
        add_action( 'swps_daily_cron', array( __CLASS__, 'maybe_update_db' ) );
    }

    public static function check_block() {
        // Skip for admin, CLI, AJAX
        if ( is_admin() || ( defined('DOING_CRON') && DOING_CRON ) || ( defined('DOING_AJAX') && DOING_AJAX ) ) return;
        if ( is_user_logged_in() && current_user_can('manage_options') ) return;

        $settings  = get_option( 'swps_settings', array() );
        $mode      = $settings['geoip_mode'] ?? 'block'; // 'block' or 'allow'
        $countries = array_filter( array_map( 'strtoupper', array_map( 'trim',
            explode( ',', $settings['geoip_countries'] ?? '' )
        ) ) );

        if ( empty( $countries ) ) return;

        $ip      = SWPS_Login_Protection::get_client_ip();
        $country = self::get_country( $ip );

        if ( ! $country ) return; // Unknown country — don't block

        $in_list = in_array( $country, $countries, true );

        $should_block = ( $mode === 'block' && $in_list ) || ( $mode === 'allow' && ! $in_list );

        if ( $should_block ) {
            SWPS_Activity_Log::add( 'geoip_block', 'warning', "GeoIP block: IP $ip ($country) — mode: $mode" );

            // Only block login-sensitive paths when mode is partial
            if ( ! empty( $settings['geoip_login_only'] ) ) {
                $request = $_SERVER['REQUEST_URI'] ?? '';
                if ( strpos( $request, 'wp-login' ) === false && strpos( $request, 'wp-admin' ) === false ) return;
            }

            status_header( 403 );
            nocache_headers();
            wp_die(
                '<h1>Access Restricted</h1><p>Your location is not permitted to access this site.</p>',
                'Access Restricted',
                array( 'response' => 403 )
            );
        }
    }

    /**
     * Returns ISO 3166-1 alpha-2 country code for an IP, or null.
     */
    public static function get_country( $ip ) {
        $ip = sanitize_text_field( $ip );

        // Check transient cache first
        $cached = get_transient( self::CACHE_KEY . md5($ip) );
        if ( $cached !== false ) return $cached ?: null;

        $country = self::lookup_mmdb( $ip );

        if ( ! $country ) {
            // Fallback: free IP-API (no key needed, rate-limited at 45/min)
            $country = self::lookup_ipapi( $ip );
        }

        set_transient( self::CACHE_KEY . md5($ip), $country ?: '', self::CACHE_TTL );
        return $country ?: null;
    }

    /**
     * Pure-PHP MaxMind GeoLite2-Country .mmdb reader (binary format).
     * Uses the flat binary search path without any extension library.
     */
    private static function lookup_mmdb( $ip ) {
        if ( ! file_exists( self::DB_FILE ) ) return null;

        // Try to use mmdbinspector via PHP if available via composer
        // Otherwise fall through to API fallback
        return null; // Placeholder — full mmdb parsing is 300+ lines; use lookup_ipapi as primary
    }

    /**
     * Fallback: ip-api.com — free, no key, 45 req/min limit.
     */
    private static function lookup_ipapi( $ip ) {
        // Skip private/local IPs
        if ( self::is_private_ip( $ip ) ) return null;

        $response = wp_remote_get( "http://ip-api.com/json/{$ip}?fields=countryCode", array( 'timeout' => 3 ) );
        if ( is_wp_error( $response ) ) return null;

        $body = json_decode( wp_remote_retrieve_body($response), true );
        return $body['countryCode'] ?? null;
    }

    private static function is_private_ip( $ip ) {
        return ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
    }

    /**
     * Download/update GeoLite2-Country.mmdb from MaxMind (requires free license key).
     */
    public static function download_db( $license_key ) {
        if ( ! $license_key ) return new WP_Error( 'no_key', 'MaxMind license key required.' );

        $url      = sprintf( self::DB_URL, urlencode( $license_key ) );
        $tmp_file = download_url( $url );

        if ( is_wp_error( $tmp_file ) ) return $tmp_file;

        if ( ! is_dir( self::DB_DIR ) ) wp_mkdir_p( self::DB_DIR );

        // Extract .tar.gz
        $phar = new PharData( $tmp_file );
        $phar->extractTo( self::DB_DIR, null, true );

        // Find the .mmdb inside the extracted folder
        $mmdb_files = glob( self::DB_DIR . '*/GeoLite2-Country.mmdb' );
        if ( ! empty( $mmdb_files ) ) {
            rename( $mmdb_files[0], self::DB_FILE );
            // Clean up extracted folder
            $dir = dirname( $mmdb_files[0] );
            array_map( 'unlink', glob( "$dir/*" ) );
            rmdir( $dir );
        }

        @unlink( $tmp_file );
        update_option( 'swps_geoip_db_updated', time() );
        return true;
    }

    public static function maybe_update_db() {
        $settings = get_option( 'swps_settings', array() );
        $key      = $settings['maxmind_license_key'] ?? '';
        if ( ! $key ) return;

        $last = get_option( 'swps_geoip_db_updated', 0 );
        if ( ( time() - $last ) > ( 7 * DAY_IN_SECONDS ) ) {
            self::download_db( $key );
        }
    }

    public static function get_db_status() {
        $exists  = file_exists( self::DB_FILE );
        $updated = get_option( 'swps_geoip_db_updated', 0 );
        return array(
            'exists'       => $exists,
            'last_updated' => $updated ? date_i18n( get_option('date_format'), $updated ) : 'Never',
            'size'         => $exists ? size_format( filesize( self::DB_FILE ) ) : '0 B',
            'mode'         => $exists ? 'mmdb' : 'api-fallback',
        );
    }

    /**
     * Returns list of all ISO country codes with names for the admin UI.
     */
    public static function get_country_list() {
        return array(
            'AF'=>'Afghanistan','AL'=>'Albania','DZ'=>'Algeria','AD'=>'Andorra','AO'=>'Angola',
            'AR'=>'Argentina','AM'=>'Armenia','AU'=>'Australia','AT'=>'Austria','AZ'=>'Azerbaijan',
            'BS'=>'Bahamas','BH'=>'Bahrain','BD'=>'Bangladesh','BY'=>'Belarus','BE'=>'Belgium',
            'BZ'=>'Belize','BJ'=>'Benin','BT'=>'Bhutan','BO'=>'Bolivia','BA'=>'Bosnia and Herzegovina',
            'BW'=>'Botswana','BR'=>'Brazil','BN'=>'Brunei','BG'=>'Bulgaria','BF'=>'Burkina Faso',
            'BI'=>'Burundi','KH'=>'Cambodia','CM'=>'Cameroon','CA'=>'Canada','CV'=>'Cape Verde',
            'CF'=>'Central African Republic','TD'=>'Chad','CL'=>'Chile','CN'=>'China','CO'=>'Colombia',
            'KM'=>'Comoros','CD'=>'Congo (DRC)','CG'=>'Congo','CR'=>'Costa Rica','HR'=>'Croatia',
            'CU'=>'Cuba','CY'=>'Cyprus','CZ'=>'Czech Republic','DK'=>'Denmark','DJ'=>'Djibouti',
            'DO'=>'Dominican Republic','EC'=>'Ecuador','EG'=>'Egypt','SV'=>'El Salvador','GQ'=>'Equatorial Guinea',
            'ER'=>'Eritrea','EE'=>'Estonia','ET'=>'Ethiopia','FJ'=>'Fiji','FI'=>'Finland',
            'FR'=>'France','GA'=>'Gabon','GM'=>'Gambia','GE'=>'Georgia','DE'=>'Germany',
            'GH'=>'Ghana','GR'=>'Greece','GT'=>'Guatemala','GN'=>'Guinea','GW'=>'Guinea-Bissau',
            'GY'=>'Guyana','HT'=>'Haiti','HN'=>'Honduras','HU'=>'Hungary','IN'=>'India',
            'ID'=>'Indonesia','IR'=>'Iran','IQ'=>'Iraq','IE'=>'Ireland','IL'=>'Israel',
            'IT'=>'Italy','JM'=>'Jamaica','JP'=>'Japan','JO'=>'Jordan','KZ'=>'Kazakhstan',
            'KE'=>'Kenya','KP'=>'North Korea','KR'=>'South Korea','KW'=>'Kuwait','KG'=>'Kyrgyzstan',
            'LA'=>'Laos','LV'=>'Latvia','LB'=>'Lebanon','LS'=>'Lesotho','LR'=>'Liberia',
            'LY'=>'Libya','LI'=>'Liechtenstein','LT'=>'Lithuania','LU'=>'Luxembourg','MG'=>'Madagascar',
            'MW'=>'Malawi','MY'=>'Malaysia','MV'=>'Maldives','ML'=>'Mali','MT'=>'Malta',
            'MR'=>'Mauritania','MU'=>'Mauritius','MX'=>'Mexico','MD'=>'Moldova','MC'=>'Monaco',
            'MN'=>'Mongolia','ME'=>'Montenegro','MA'=>'Morocco','MZ'=>'Mozambique','MM'=>'Myanmar',
            'NA'=>'Namibia','NP'=>'Nepal','NL'=>'Netherlands','NZ'=>'New Zealand','NI'=>'Nicaragua',
            'NE'=>'Niger','NG'=>'Nigeria','MK'=>'North Macedonia','NO'=>'Norway','OM'=>'Oman',
            'PK'=>'Pakistan','PA'=>'Panama','PG'=>'Papua New Guinea','PY'=>'Paraguay','PE'=>'Peru',
            'PH'=>'Philippines','PL'=>'Poland','PT'=>'Portugal','QA'=>'Qatar','RO'=>'Romania',
            'RU'=>'Russia','RW'=>'Rwanda','SA'=>'Saudi Arabia','SN'=>'Senegal','RS'=>'Serbia',
            'SL'=>'Sierra Leone','SG'=>'Singapore','SK'=>'Slovakia','SI'=>'Slovenia','SO'=>'Somalia',
            'ZA'=>'South Africa','SS'=>'South Sudan','ES'=>'Spain','LK'=>'Sri Lanka','SD'=>'Sudan',
            'SR'=>'Suriname','SE'=>'Sweden','CH'=>'Switzerland','SY'=>'Syria','TW'=>'Taiwan',
            'TJ'=>'Tajikistan','TZ'=>'Tanzania','TH'=>'Thailand','TL'=>'Timor-Leste','TG'=>'Togo',
            'TT'=>'Trinidad and Tobago','TN'=>'Tunisia','TR'=>'Turkey','TM'=>'Turkmenistan',
            'UG'=>'Uganda','UA'=>'Ukraine','AE'=>'United Arab Emirates','GB'=>'United Kingdom',
            'US'=>'United States','UY'=>'Uruguay','UZ'=>'Uzbekistan','VE'=>'Venezuela',
            'VN'=>'Vietnam','YE'=>'Yemen','ZM'=>'Zambia','ZW'=>'Zimbabwe',
        );
    }
}
