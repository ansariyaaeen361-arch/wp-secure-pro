<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_White_Label {

    public static function init() {
        $settings = get_option( 'swps_white_label', array() );
        if ( empty( $settings['enabled'] ) ) return;

        add_filter( 'all_plugins',          array( __CLASS__, 'hide_in_plugin_list' ) );
        add_action( 'admin_menu',           array( __CLASS__, 'rename_menu' ), 9999 );
        add_action( 'admin_bar_menu',       array( __CLASS__, 'rename_admin_bar' ), 9999 );
        add_action( 'admin_enqueue_scripts',array( __CLASS__, 'custom_branding_css' ) );
        add_filter( 'update_plugins_wp-secure-pro/wp-secure-pro.php', '__return_false' );
        add_filter( 'plugin_action_links_wp-secure-pro/wp-secure-pro.php', array( __CLASS__, 'remove_settings_link' ) );
    }

    private static function get( $key, $default = '' ) {
        $settings = get_option( 'swps_white_label', array() );
        return $settings[$key] ?? $default;
    }

    public static function hide_in_plugin_list( $plugins ) {
        if ( ! self::get('hide_plugin') ) return $plugins;
        unset( $plugins['wp-secure-pro/wp-secure-pro.php'] );
        return $plugins;
    }

    public static function rename_menu() {
        global $menu, $submenu;
        $custom_name = self::get('menu_name');
        if ( ! $custom_name ) return;

        foreach ( $menu as $pos => $item ) {
            if ( isset($item[2]) && $item[2] === 'swps-dashboard' ) {
                $menu[$pos][0] = esc_html( $custom_name );
                break;
            }
        }

        if ( isset($submenu['swps-dashboard']) ) {
            foreach ( $submenu['swps-dashboard'] as $pos => $item ) {
                if ( $item[2] === 'swps-dashboard' ) {
                    $submenu['swps-dashboard'][$pos][0] = esc_html( $custom_name );
                    break;
                }
            }
        }
    }

    public static function rename_admin_bar() {
        // No admin bar item to rename by default
    }

    public static function custom_branding_css() {
        $logo_url    = self::get('logo_url');
        $accent      = self::get('accent_color', '#2563eb');
        $custom_name = self::get('menu_name');

        $css = '';

        if ( $accent ) {
            $css .= ":root { --swps-primary: " . sanitize_hex_color($accent) . " !important; }\n";
        }

        if ( $logo_url ) {
            $css .= ".swps-logo-area { background-image: url('" . esc_url($logo_url) . "') !important; }\n";
            $css .= ".swps-logo-text { display: none !important; }\n";
        }

        if ( $css ) {
            wp_add_inline_style( 'swps-admin-style', $css );
        }
    }

    public static function remove_settings_link( $links ) {
        unset( $links['settings'] );
        return $links;
    }

    /* ---- Client report generation ---- */

    public static function generate_report() {
        $brand   = self::get('company_name', 'WP Secure Pro');
        $logo    = self::get('logo_url');
        $scan    = get_option('swps_last_scan', array());
        $vuln    = get_option('swps_last_vuln_scan', array());
        $bl      = get_option('swps_blacklist_last_check', array());

        $score        = self::calculate_score();
        $scanned_date = ! empty($scan['time']) ? date_i18n(get_option('date_format'), $scan['time']) : 'Not run';
        $threats      = $scan['threats'] ?? array();

        ob_start();
        ?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body{font-family:Arial,sans-serif;color:#222;margin:0;padding:30px;background:#fff}
h1{font-size:24px;margin-bottom:4px}
.score{font-size:48px;font-weight:bold;color:<?php echo $score >= 70 ? '#16a34a' : ($score >= 40 ? '#d97706' : '#dc2626'); ?>}
table{border-collapse:collapse;width:100%;margin-top:16px}
th,td{border:1px solid #ddd;padding:8px 12px;text-align:left;font-size:13px}
th{background:#f5f5f5}
.ok{color:#16a34a}.warn{color:#d97706}.crit{color:#dc2626}
.footer{margin-top:40px;font-size:11px;color:#888}
</style>
</head>
<body>
<?php if ($logo): ?><img src="<?php echo esc_url($logo); ?>" style="max-height:60px;margin-bottom:16px"><br><?php endif; ?>
<h1><?php echo esc_html($brand); ?> — Security Report</h1>
<p>Site: <strong><?php echo esc_html(get_site_url()); ?></strong> &nbsp;|&nbsp; Generated: <?php echo date_i18n('M j, Y H:i'); ?></p>
<p>Security Score: <span class="score"><?php echo $score; ?>/100</span></p>

<h2>Scan Results (<?php echo esc_html($scanned_date); ?>)</h2>
<?php if (empty($threats)): ?>
<p class="ok">No malware or threats detected.</p>
<?php else: ?>
<table>
<tr><th>File</th><th>Threat</th><th>Type</th></tr>
<?php foreach ($threats as $t): ?>
<tr><td><?php echo esc_html($t['file'] ?? ''); ?></td><td class="crit"><?php echo esc_html($t['reason'] ?? ''); ?></td><td><?php echo esc_html($t['type'] ?? ''); ?></td></tr>
<?php endforeach; ?>
</table>
<?php endif; ?>

<h2>Blacklist Status</h2>
<table>
<tr><th>Service</th><th>Status</th></tr>
<?php foreach ($bl as $key => $data): if (!is_array($data)) continue; ?>
<tr>
<td><?php echo esc_html($data['name'] ?? $key); ?></td>
<td class="<?php echo $data['listed'] ? 'crit' : 'ok'; ?>"><?php echo $data['listed'] ? 'BLACKLISTED' : ($data['listed'] === null ? 'Unknown' : 'Clean'); ?></td>
</tr>
<?php endforeach; ?>
</table>

<div class="footer">Report generated by <?php echo esc_html($brand); ?></div>
</body>
</html>
        <?php
        return ob_get_clean();
    }

    private static function calculate_score() {
        $score = 100;
        $scan  = get_option('swps_last_scan', array());
        $bl    = get_option('swps_blacklist_last_check', array());

        if ( ! empty($scan['threats']) ) $score -= min( count($scan['threats']) * 10, 40 );
        if ( SWPS_Blacklist_Monitor::is_any_blacklisted($bl) ) $score -= 30;

        $h = get_option('swps_hardening', array());
        if ( empty($h['disable_xmlrpc']) )  $score -= 5;
        if ( empty($h['remove_wp_version']) ) $score -= 5;

        return max(0, $score);
    }
}
