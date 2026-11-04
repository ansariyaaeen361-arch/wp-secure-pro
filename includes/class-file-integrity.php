<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_File_Integrity {

    const BASELINE_OPTION = 'swps_file_baseline';
    const LAST_SCAN_OPTION = 'swps_fim_last_scan';
    const PRE_BASELINE_SCAN_OPTION = 'swps_pre_baseline_scan';
    // A clean pre-baseline scan only counts if it ran recently — otherwise
    // someone could scan clean, wait a week while something gets planted,
    // then baseline without ever re-checking.
    const PRE_BASELINE_SCAN_MAX_AGE = HOUR_IN_SECONDS;

    /**
     * Quarantined files are moved here. Preferred location is OUTSIDE the
     * webroot (a sibling of ABSPATH) so quarantined malware/secrets have no
     * URL at all — this does not depend on .htaccess, which OpenLiteSpeed and
     * many managed stacks do not enforce. Quarantine fails closed if no
     * webroot-external directory can be created.
     */
    public static function quarantine_dir() {
        static $dir = null;
        if ( $dir !== null ) return $dir;

        $outside = dirname( rtrim( ABSPATH, '/\\' ) ) . '/swps-quarantine/';
        if ( wp_mkdir_p( $outside ) && is_writable( $outside ) ) {
            $dir = $outside;
        } else $dir = '';
        return $dir;
    }

    public static function init() {
        add_action( 'swps_hourly_check', array( __CLASS__, 'run_check' ) );
        add_action( 'admin_init',        array( __CLASS__, 'maybe_auto_baseline' ) );
        add_action( 'wp_ajax_swps_fim_baseline',  array( __CLASS__, 'ajax_create_baseline' ) );
        add_action( 'wp_ajax_swps_fim_pre_baseline_scan', array( __CLASS__, 'ajax_pre_baseline_scan' ) );
        add_action( 'wp_ajax_swps_fim_scan',      array( __CLASS__, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_swps_fim_restore',   array( __CLASS__, 'ajax_restore_file' ) );
        add_action( 'wp_ajax_swps_fim_ignore',    array( __CLASS__, 'ajax_ignore_file' ) );
        add_action( 'wp_ajax_swps_fim_trust_update', array( __CLASS__, 'ajax_trust_update' ) );
        add_action( 'wp_ajax_swps_fim_trust_all',    array( __CLASS__, 'ajax_trust_all_updates' ) );
        add_action( 'wp_ajax_swps_fim_view_diff', array( __CLASS__, 'ajax_view_diff' ) );

        // Fix: without this, a totally routine plugin/theme/core update makes
        // every file it touches show up as a "changed" issue forever (the
        // baseline never moves on its own), so Full Scan nags about the same
        // legitimate update every single run until an admin manually
        // Quarantines or Ignores each file. A per-file "accept" button was
        // considered and rejected — it invites blind-clicking, since the UI
        // has no diff view, which would make it easy to wave through an
        // actual compromise along with routine noise. Auto-refreshing the
        // baseline ONLY for files WordPress's own updater just touched
        // avoids that: the "is this legitimate" judgment is made by
        // WordPress's verified update mechanism, not a reflexive click, and
        // anything NOT covered by a real update — the pattern that actually
        // indicates tampering — still gets flagged as before.
        add_action( 'upgrader_process_complete', array( __CLASS__, 'refresh_baseline_after_update' ), 10, 2 );
    }

    /** Re-hashes just the files belonging to whatever WordPress's own
     *  updater just installed/updated, so that legitimate change stops
     *  being reported without touching the baseline for anything else. */
    public static function refresh_baseline_after_update( $upgrader_object, $hook_extra ) {
        $type   = $hook_extra['type'] ?? '';
        $prefixes = array();

        if ( $type === 'plugin' ) {
            $plugins = $hook_extra['plugins'] ?? ( isset($hook_extra['plugin']) ? array($hook_extra['plugin']) : array() );
            foreach ( $plugins as $plugin_file ) {
                $dir = dirname( $plugin_file );
                if ( $dir && $dir !== '.' ) $prefixes[] = 'wp-content/plugins/' . $dir;
            }
        } elseif ( $type === 'theme' ) {
            $themes = $hook_extra['themes'] ?? ( isset($hook_extra['theme']) ? array($hook_extra['theme']) : array() );
            foreach ( $themes as $stylesheet ) {
                $prefixes[] = 'wp-content/themes/' . $stylesheet;
            }
        } elseif ( $type === 'core' ) {
            $prefixes[] = 'wp-admin';
            $prefixes[] = 'wp-includes';
            $prefixes[] = ''; // root *.php files
        }

        if ( empty($prefixes) ) return;
        self::refresh_baseline_for_prefixes( $prefixes );
        self::run_scan(); // reflect the clean state immediately rather than waiting for the next hourly check
    }

    /**
     * Explicit, admin-attributed "I updated this myself" action — covers
     * updates that didn't go through WordPress's own updater (FTP, a
     * host-level deploy tool, manually extracting a zip) and so never fired
     * upgrader_process_complete. Deliberately NOT a silent/automatic trust
     * path: it's one click, it's logged with who clicked it and when, and —
     * same as the update-hook path — it still runs every file through the
     * malware-signature check first, so an admin can't accidentally
     * whitelist a genuinely malicious file just because it arrived bundled
     * with 80 legitimate ones.
     */
    public static function ajax_trust_update() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $prefix = sanitize_text_field( wp_unslash( $_POST['prefix'] ?? '' ) );
        if ( ! $prefix ) wp_send_json_error('Missing prefix.');

        $skipped = self::refresh_baseline_for_prefixes( array( $prefix ) );
        self::run_scan();

        $user = wp_get_current_user();
        $msg  = "Trusted update to \"$prefix\" ({$user->user_login})" . ( $skipped ? " — $skipped file(s) with a malware-signature match were NOT trusted and still need review." : '.' );
        SWPS_Activity_Log::add( 'fim_trust_update', $skipped ? 'warning' : 'info', $msg );

        wp_send_json_success( array(
            'message' => $skipped
                ? "Trusted — but $skipped file(s) still look suspicious and were left flagged for your review."
                : 'Trusted. These changes will no longer show as an issue.',
        ) );
    }

    /**
     * One-click cleanup for the backlog that piles up when several real
     * plugin/theme/core updates landed before the baseline was ever
     * refreshed for them (e.g. this plugin was only just installed/updated
     * on a site that already had months of normal auto-updates behind it).
     * Walks every CURRENT File Integrity change exactly once and re-hashes
     * it into the baseline — grouped by plugin/theme/core the same way the
     * Full Scan UI groups them, so this is just "I did this" run in bulk,
     * not a new trust mechanism. The one hard line: a file whose severity
     * is already 'critical' (a malware-signature hit, forced upstream in
     * run_scan()) is NEVER included here, no matter how many clean files
     * surround it — those still require the admin to look at them, or
     * explicitly Quarantine/remove them, one at a time.
     */
    public static function ajax_trust_all_updates() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $stats   = self::get_stats();
        $changes = $stats['changes'] ?? array();

        $prefix_of = function( $file ) {
            if ( preg_match('#^(wp-content/plugins/[^/]+)/#', $file, $m) ) return $m[1];
            if ( preg_match('#^(wp-content/themes/[^/]+)/#',  $file, $m) ) return $m[1];
            if ( strpos( $file, 'wp-admin/' )    === 0 ) return 'wp-admin';
            if ( strpos( $file, 'wp-includes/' ) === 0 ) return 'wp-includes';
            if ( strpos( $file, '/' ) === false )        return ''; // root *.php
            return null;
        };

        $prefixes = array();
        $critical_count = 0;
        foreach ( $changes as $change ) {
            if ( $change['severity'] === 'critical' ) { $critical_count++; continue; }
            $p = $prefix_of( $change['file'] );
            if ( $p !== null && ! in_array( $p, $prefixes, true ) ) $prefixes[] = $p;
        }

        if ( ! $prefixes ) {
            wp_send_json_error( $critical_count
                ? "All $critical_count remaining change(s) are malware-flagged and must be reviewed individually — nothing safe to bulk-trust."
                : 'Nothing to trust — no non-critical changes found.'
            );
        }

        $skipped = self::refresh_baseline_for_prefixes( $prefixes );
        self::run_scan();

        $user = wp_get_current_user();
        $msg  = "Bulk-trusted current changes across " . count($prefixes) . " plugin/theme/core group(s) ({$user->user_login})"
              . ( $skipped ? " — $skipped file(s) with a malware-signature match were NOT trusted." : '.' )
              . ( $critical_count ? " $critical_count critical (malware-flagged) change(s) were left for manual review." : '' );
        SWPS_Activity_Log::add( 'fim_trust_update', ( $skipped || $critical_count ) ? 'warning' : 'info', $msg );

        wp_send_json_success( array(
            'groups'   => count( $prefixes ),
            'skipped'  => $skipped,
            'critical' => $critical_count,
            'message'  => 'Trusted ' . count($prefixes) . ' group(s).'
                . ( $skipped ? " $skipped file(s) stayed flagged (malware match)." : '' )
                . ( $critical_count ? " $critical_count critical issue(s) still need manual review." : '' ),
        ) );
    }

    /**
     * Returns enough to let the admin SEE what changed, not just a bare
     * filename — this is the context every researched competitor's admins
     * end up relying on manually anyway (Wordfence support explicitly tells
     * users to check a diff/changelog themselves). For WordPress.org-hosted
     * core/plugin/theme files we have a real "official" copy to diff
     * against (the same source Auto-Fix downloads from); for anything else
     * there's no stored history to diff against (only a hash was kept, by
     * design — storing full content for every monitored file would bloat
     * the database), so only the current content is shown, honestly labeled
     * as such rather than faking a diff.
     */
    public static function ajax_view_diff() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $rel = sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) );
        $rel = ltrim( str_replace('..', '', $rel), '/\\' );
        $full = ABSPATH . $rel;
        if ( ! $rel || ! file_exists( $full ) || ! is_readable( $full ) ) {
            wp_send_json_error('File not found or not readable.');
        }
        if ( filesize( $full ) > 2 * 1024 * 1024 ) {
            wp_send_json_error('File is too large to display here (over 2MB) — view it directly on the server instead.');
        }
        $current = file_get_contents( $full );

        $official  = null;
        $has_malware = false;
        if ( strpos( $rel, 'wp-admin/' ) === 0 || strpos( $rel, 'wp-includes/' ) === 0 || strpos( $rel, '/' ) === false ) {
            if ( class_exists('SWPS_Core_Repair') ) {
                $checksums = SWPS_Core_Repair::get_checksums();
                if ( $checksums && isset( $checksums[ $rel ] ) ) {
                    $version = get_bloginfo('version');
                    $resp = wp_remote_get( "https://core.svn.wordpress.org/tags/{$version}/{$rel}", array('timeout'=>20) );
                    if ( ! is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200 ) $official = wp_remote_retrieve_body($resp);
                }
            }
        } elseif ( class_exists('SWPS_Plugin_Theme_Repair') && preg_match('#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m ) && SWPS_Plugin_Theme_Repair::is_wporg_plugin( $m[1] ) ) {
            $official = self::fetch_wporg_official_content( 'plugin', $m[1], $m[2] );
        } elseif ( class_exists('SWPS_Plugin_Theme_Repair') && preg_match('#^wp-content/themes/([^/]+)/(.+)$#', $rel, $m ) && SWPS_Plugin_Theme_Repair::is_wporg_theme( $m[1] ) ) {
            $official = self::fetch_wporg_official_content( 'theme', $m[1], $m[2] );
        }

        if ( class_exists('SWPS_Malware_DNA') ) {
            $has_malware = ! empty( SWPS_Malware_DNA::scan_file( $full ) );
        }

        wp_send_json_success( array(
            'file'          => $rel,
            'current'       => mb_convert_encoding( $current, 'UTF-8', 'UTF-8' ),
            'official'      => $official !== null ? mb_convert_encoding( $official, 'UTF-8', 'UTF-8' ) : null,
            'has_official'  => $official !== null,
            'has_malware'   => $has_malware,
        ) );
    }

    private static function fetch_wporg_official_content( $kind, $slug, $inner ) {
        $v = $kind === 'plugin'
            ? SWPS_Plugin_Theme_Repair::installed_plugin_version( $slug )
            : SWPS_Plugin_Theme_Repair::installed_theme_version( $slug );
        if ( ! $v ) return null;

        $url = $kind === 'plugin'
            ? sprintf( SWPS_Plugin_Theme_Repair::PLUGIN_SVN, $slug, $v, $inner )
            : sprintf( SWPS_Plugin_Theme_Repair::THEME_SVN, $slug, $v, $inner );

        $resp = wp_remote_get( $url, array('timeout'=>20) );
        if ( is_wp_error($resp) || wp_remote_retrieve_response_code($resp) !== 200 ) return null;
        return wp_remote_retrieve_body( $resp );
    }

    /** Re-hashes every currently-monitored file under any of the given
     *  relative path prefixes and updates just those entries in the
     *  baseline, leaving everything else untouched. Also drops baseline
     *  entries for files that were removed as part of the same update.
     *  Returns the count of files skipped due to a malware-signature hit. */
    public static function refresh_baseline_for_prefixes( $prefixes ) {
        $baseline = get_option( self::BASELINE_OPTION, array() );
        if ( empty($baseline) ) return 0; // no baseline yet — nothing to refresh

        $matches_prefix = function( $rel ) use ( $prefixes ) {
            foreach ( $prefixes as $p ) {
                if ( $p === '' ) { if ( strpos($rel, '/') === false ) return true; continue; } // root *.php
                if ( strpos( $rel, rtrim($p, '/') . '/' ) === 0 ) return true;
            }
            return false;
        };

        // Drop stale entries for files under these prefixes that no longer exist.
        foreach ( $baseline as $rel => $data ) {
            if ( $matches_prefix($rel) && ! file_exists( ABSPATH . $rel ) ) unset( $baseline[$rel] );
        }

        // Re-hash current files under these prefixes (adds new ones too).
        //
        // Fix: a file that fires WordPress's own update hook is still not
        // proof of safety by itself — a compromised build pipeline or a
        // supply-chain-tampered release can ship through the exact same
        // "legitimate update" channel (the real-world pattern behind the
        // 3CX and xz-utils incidents researched for this). Any file in this
        // batch that matches a malware signature is skipped here — it stays
        // OUT of the trusted baseline and keeps showing as a flagged change
        // on the next scan, even though the update event itself was real.
        $skipped = 0;
        foreach ( self::get_monitored_files() as $path ) {
            $rel = self::rel($path);
            if ( ! $matches_prefix($rel) || ! is_readable($path) ) continue;
            if ( self::content_malware_hit( $path ) ) { $skipped++; continue; }
            $baseline[$rel] = array(
                'hash'  => hash_file( 'sha256', $path ),
                'size'  => filesize($path),
                'mtime' => filemtime($path),
            );
        }

        update_option( self::BASELINE_OPTION, $baseline );
        return $skipped;
    }

    /* ── Baseline ─────────────────────────────────────────────────────────── */

    /**
     * A baseline is only as trustworthy as the moment it was taken — if a
     * backdoor is already sitting on the site the first time this runs,
     * create_baseline() would hash it right alongside everything else and
     * "bless" it as permanently normal, never to be flagged again. This is
     * now gated behind run_pre_baseline_scan() coming back clean, recently
     * (see ajax_create_baseline() / maybe_auto_baseline()) — the raw
     * version below is kept as the actual hashing step, called only after
     * that gate passes.
     */
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

        $gate = self::check_pre_baseline_gate();
        if ( $gate !== true ) wp_send_json_error( $gate );

        $count = self::create_baseline();
        wp_send_json_success( array( 'count' => $count, 'message' => "Baseline created with $count files." ) );
    }

    /** Returns true if it's safe to baseline right now, or an error string explaining why not. */
    private static function check_pre_baseline_gate() {
        $scan = get_option( self::PRE_BASELINE_SCAN_OPTION, array() );
        if ( empty( $scan['scanned_at'] ) ) {
            return 'Run "Scan Before Baseline" first — a baseline taken blind could lock in an existing infection as "normal" forever.';
        }
        if ( ( time() - $scan['scanned_at'] ) > self::PRE_BASELINE_SCAN_MAX_AGE ) {
            return 'Your pre-baseline scan is over an hour old — run "Scan Before Baseline" again to make sure nothing changed since.';
        }
        if ( ! empty( $scan['flagged'] ) ) {
            return count( $scan['flagged'] ) . ' file(s) look compromised — remove/clean them first (Quarantine or manually), then run "Scan Before Baseline" again. Baseline cannot be created while they\'re still there.';
        }
        return true;
    }

    /**
     * Scans EVERY monitored file — core, and plugins/themes whether or not
     * they're on WordPress.org — for malware signatures, the one check that
     * doesn't depend on having an official source to compare against. Core
     * files also get a cheap bulk checksum comparison (one WordPress.org
     * API call) as a second, independent check. Deliberately does NOT do a
     * per-file official-content fetch for every plugin/theme file here —
     * that's a real HTTP request per file and would be far too slow across
     * thousands of files; that check already exists on demand (Auto Fix /
     * View diff) for an individual flagged file once something else (the
     * malware scan) has pointed at it.
     */
    public static function run_pre_baseline_scan() {
        $files   = self::get_monitored_files();
        $flagged = array();

        $core_checksums = class_exists('SWPS_Core_Repair') ? SWPS_Core_Repair::get_checksums() : false;

        foreach ( $files as $path ) {
            if ( ! is_readable( $path ) ) continue;
            $rel = self::rel( $path );

            $malware = self::content_malware_hit( $path );
            if ( $malware ) {
                $flagged[] = array( 'file' => $rel, 'reason' => 'malware_signature', 'detail' => $malware );
                continue;
            }

            if ( $core_checksums && isset( $core_checksums[ $rel ] ) ) {
                if ( md5_file( $path ) !== $core_checksums[ $rel ] ) {
                    $flagged[] = array( 'file' => $rel, 'reason' => 'core_checksum_mismatch', 'detail' => '' );
                }
            }
        }

        // wp-content/uploads isn't in get_monitored_files() at all (see that
        // method) — it's media, constantly growing from normal site use, so
        // hash-tracking every file there would be pure noise. But a PHP
        // file's mere PRESENCE there is already suspicious regardless of
        // content (no legitimate upload is ever a .php file), so it's
        // checked here as its own, much cheaper signal.
        if ( class_exists('SWPS_DB_Monitor') ) {
            $uploads = wp_upload_dir();
            foreach ( SWPS_DB_Monitor::find_php_in_uploads( $uploads['basedir'] ?? '', 50 ) as $uf ) {
                $flagged[] = array( 'file' => ltrim( str_replace( ABSPATH, '', $uf ), '/\\' ), 'reason' => 'php_in_uploads', 'detail' => '' );
            }
        }

        $result = array(
            'scanned_at'   => time(),
            'total_files'  => count( $files ),
            'flagged'      => $flagged,
        );
        update_option( self::PRE_BASELINE_SCAN_OPTION, $result, false );

        if ( ! empty( $flagged ) ) {
            SWPS_Activity_Log::add( 'fim_pre_baseline_dirty', 'critical',
                count( $flagged ) . ' file(s) flagged before baseline could be created — site may already be compromised.' );
        } else {
            SWPS_Activity_Log::add( 'fim_pre_baseline_clean', 'info',
                'Pre-baseline scan clean — ' . count( $files ) . ' files checked, safe to baseline.' );
        }

        return $result;
    }

    public static function ajax_pre_baseline_scan() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        wp_send_json_success( self::run_pre_baseline_scan() );
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
            // Fix: this used to baseline immediately on first run — on a
            // fresh install there's no history to compare against, so if a
            // backdoor was ALREADY sitting on the site the moment this
            // fired, it would get hashed right along with everything else
            // and permanently "blessed" as normal. Now it scans for malware
            // signatures (and checks core files against WordPress.org's
            // checksums) FIRST; only a clean result auto-baselines. A dirty
            // result leaves the baseline empty — effectively holding FIM
            // off — and logs a critical Activity Log entry so the owner
            // sees it, rather than silently normalizing an infection.
            // Rate-limited so a site that stays dirty doesn't re-run this on
            // every single admin page load.
            if ( get_transient( 'swps_auto_prebaseline_lock' ) ) return;
            set_transient( 'swps_auto_prebaseline_lock', 1, 10 * MINUTE_IN_SECONDS );

            $scan = self::run_pre_baseline_scan();
            if ( empty( $scan['flagged'] ) ) {
                self::create_baseline();
                update_option( 'swps_fim_plugin_version', SWPS_VERSION );
            }
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
        $baseline_dirty = false;

        // A core update (new WordPress version) can legitimately ADD brand
        // new files under wp-admin/ or wp-includes/ (e.g. a new bundled
        // library) — these aren't tampering, they're bundled WordPress.org
        // source. Checked against the official checksum list for the
        // currently-running version: an exact md5 match there is as strong a
        // "this is genuinely WordPress core" signal as the malware scan is
        // for everything else, so it's allowed to silently absorb too.
        // A core file that's MISSING from that list, or whose hash doesn't
        // match it, stays fully visible — that combination (new file in
        // wp-admin/wp-includes NOT part of the official distribution) is
        // exactly what a planted core-level backdoor would look like.
        $core_checksums = class_exists('SWPS_Core_Repair') ? SWPS_Core_Repair::get_checksums() : false;

        // Security invariant: only a file that is cryptographically verified
        // against the current WordPress core checksum list may be folded into
        // the baseline automatically. A custom backdoor is normally not in a
        // signature list, so silently accepting plugin/theme changes makes
        // file integrity monitoring ineffective after the first scan.
        foreach ( $files as $path ) {
            $rel = self::rel($path);
            if ( in_array($rel, $ignored) ) continue;
            if ( ! is_readable($path) ) continue;

            $hash = hash_file( 'sha256', $path );
            $is_core = self::get_severity($rel) === 'critical';
            // Core file whose hash matches the official checksum for the
            // currently-running WordPress version — provably stock core,
            // whether brand new (a core update bundling a new file) or
            // changed back to match a just-updated version.
            $is_official_core = $is_core && $core_checksums && isset( $core_checksums[$rel] ) && md5_file($path) === $core_checksums[$rel];

            if ( ! isset($baseline[$rel]) ) {
                $malware = self::content_malware_hit( $path );
                if ( $is_official_core ) {
                    $baseline[$rel] = array( 'hash' => $hash, 'size' => filesize($path), 'mtime' => filemtime($path) );
                    $baseline_dirty = true;
                    continue;
                }
                $entry = array( 'file' => $rel, 'type' => 'added', 'severity' => $malware ? 'critical' : 'warning' );
                if ( $malware ) $entry['malware_sig'] = $malware;
                $changes[] = $entry;
            } elseif ( $hash !== $baseline[$rel]['hash'] ) {
                $malware = self::content_malware_hit( $path );
                if ( $is_official_core ) {
                    $baseline[$rel] = array( 'hash' => $hash, 'size' => filesize($path), 'mtime' => filemtime($path) );
                    $baseline_dirty = true;
                    continue;
                }
                $entry = array(
                    'file'        => $rel,
                    'type'        => 'modified',
                    'severity'    => $malware ? 'critical' : self::get_severity($rel),
                    'old_hash'    => $baseline[$rel]['hash'],
                    'new_hash'    => $hash,
                    'mtime'       => date_i18n( 'Y-m-d H:i:s', filemtime($path) ),
                );
                if ( $malware ) $entry['malware_sig'] = $malware;
                $changes[] = $entry;
            }
        }

        // Every deletion is material. A removed security plugin, scanner, or
        // webshell evidence must never be silently removed from the baseline.
        foreach ( $baseline as $rel => $data ) {
            if ( in_array($rel, $ignored) ) continue;
            $full = ABSPATH . $rel;
            if ( ! file_exists($full) ) {
                $changes[] = array( 'file' => $rel, 'type' => 'deleted', 'severity' => self::get_severity($rel) === 'critical' ? 'critical' : 'warning' );
            }
        }

        if ( $baseline_dirty ) update_option( self::BASELINE_OPTION, $baseline );

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
                    'WP Secure Pro: Critical File Changes Detected',
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
        $rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
        if ( $rel_path === '' || strpos( $rel_path, '..' ) !== false ) return false;
        $root = realpath( ABSPATH );
        $src  = realpath( ABSPATH . $rel_path );
        if ( ! $root || ! $src || ! self::is_path_within( $src, $root ) || ! is_file( $src ) || is_link( $src ) ) return false;

        $qdir = self::quarantine_dir();
        if ( ! $qdir ) return false;

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

        $quarantine_dir = self::quarantine_dir();
        $qroot = $quarantine_dir ? realpath( $quarantine_dir ) : false;
        $qfile = realpath( $quarantine_path );
        if ( ! $qroot || ! $qfile || ! self::is_path_within( $qfile, $qroot ) || ! is_file( $qfile ) || is_link( $qfile ) ) {
            wp_send_json_error('Invalid path');
        }

        // Fix: path traversal check on destination — prevents writing outside webroot
        $original_path = ltrim( str_replace( '\\', '/', $original_path ), '/' );
        if ( strpos( $original_path, '..' ) !== false ) {
            wp_send_json_error('Invalid path');
        }
        $root            = realpath( ABSPATH );
        $resolved        = $root . '/' . $original_path;
        $real_target_dir = realpath( dirname( $resolved ) );
        if ( ! $root || $real_target_dir === false || ! self::is_path_within( $real_target_dir, $root ) ) {
            wp_send_json_error('Invalid path');
        }

        if ( rename( $qfile, $resolved ) ) {
            SWPS_Activity_Log::add( 'file_restored', 'warning', "File restored from quarantine: $original_path" );
            wp_send_json_success('File restored.');
        } else {
            wp_send_json_error('Restore failed.');
        }
    }

    private static function is_path_within( $path, $base ) {
        $path = rtrim( wp_normalize_path( $path ), '/' );
        $base = rtrim( wp_normalize_path( $base ), '/' );
        return $path === $base || strpos( $path, $base . '/' ) === 0;
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

    /** Returns the highest-confidence malware signature match for a file's
     *  CURRENT content, or null if clean / scanner unavailable. Reuses the
     *  Malware DNA scanner so there's one signature list to maintain, not
     *  two. Only PHP/JS-extension files are worth the cost here — the same
     *  file types FIM already monitors. */
    private static function content_malware_hit( $path ) {
        if ( ! class_exists( 'SWPS_Malware_DNA' ) ) return null;
        $findings = SWPS_Malware_DNA::scan_file( $path );
        if ( empty( $findings ) ) return null;
        // Prefer a 'critical'-severity DNA signature if one hit, else the first match.
        foreach ( $findings as $f ) if ( ( $f['severity'] ?? '' ) === 'critical' ) return $f['sig_id'];
        return $findings[0]['sig_id'] ?? null;
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
