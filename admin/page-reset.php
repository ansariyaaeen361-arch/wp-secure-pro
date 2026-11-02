<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php $domain = parse_url( home_url(), PHP_URL_HOST ); ?>
<div class="wrap swps-wrap">
    <div class="swps-header" style="border-left-color:#dc2626">
        <span class="dashicons dashicons-warning" style="font-size:30px;color:#dc2626"></span>
        <div>
            <h1>Reset &amp; Delete Data</h1>
            <p>Permanently erase every trace of WP Secure Pro's data from this site.</p>
        </div>
    </div>

    <div class="swps-card" style="border:1px solid #fecaca">
        <div class="swps-card-header" style="background:#fef2f2;color:#991b1b">
            <span class="dashicons dashicons-trash"></span> This cannot be undone
        </div>
        <div class="swps-card-body">
            <p>Clicking the button below deletes <strong>all</strong> of the following, permanently:</p>
            <ul class="swps-list">
                <li>Every setting in every WP Secure Pro section (WAF, 2FA, Hardening, Headers, Honeypot — everything)</li>
                <li>Activity Log, Blocked IPs, login-attempt history</li>
                <li>File Integrity baseline, scan results, Full Scan history, quarantined files</li>
                <li>2FA secrets configured on any user account</li>
                <li>Cached GeoIP database, exported SIEM logs</li>
                <li>All scheduled scans/checks (re-created fresh afterward)</li>
            </ul>
            <p>The plugin itself <strong>stays installed and active</strong> — only its data is wiped. Afterward the site looks exactly like the moment WP Secure Pro was first installed, with the same safe-by-default settings.</p>
            <p class="description">The plugin cannot log this action after the fact — the log is one of the things being deleted. If you want a record, take a screenshot of your current Activity Log first.</p>

            <div style="margin-top:20px;padding:16px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px">
                <label style="display:block;font-weight:600;margin-bottom:8px;color:#991b1b">
                    Type your site's domain (<code><?php echo esc_html($domain); ?></code>) to confirm:
                </label>
                <input type="text" id="swps-reset-confirm-input" class="regular-text" placeholder="<?php echo esc_attr($domain); ?>" autocomplete="off">
                <button type="button" id="swps-reset-btn" class="swps-btn swps-btn-danger" disabled style="margin-left:10px;opacity:.5">
                    🗑️ Delete All Data
                </button>
            </div>
        </div>
    </div>
</div>

<script>
(function(){
    var DOMAIN = <?php echo wp_json_encode($domain); ?>;
    var input  = document.getElementById('swps-reset-confirm-input');
    var btn    = document.getElementById('swps-reset-btn');

    input.addEventListener('input', function(){
        var match = input.value.trim().toLowerCase() === DOMAIN.toLowerCase();
        btn.disabled = !match;
        btn.style.opacity = match ? '1' : '.5';
    });

    btn.addEventListener('click', function(){
        if (!confirm('Last check: this permanently deletes ALL WP Secure Pro settings, logs and data on ' + DOMAIN + '. There is no undo. Continue?')) return;
        btn.disabled = true;
        btn.textContent = 'Deleting…';
        jQuery.post(swps_vars.url, {
            action: 'swps_factory_reset',
            nonce: swps_vars.nonce,
            confirm_domain: input.value.trim()
        }, function(res){
            if (res && res.success) {
                alert((res.data && res.data.message) || 'Data deleted.');
                location.reload();
            } else {
                alert((res && res.data) || 'Reset failed.');
                btn.disabled = false;
                btn.textContent = '🗑️ Delete All Data';
            }
        }).fail(function(){
            alert('Request failed (server/network error).');
            btn.disabled = false;
            btn.textContent = '🗑️ Delete All Data';
        });
    });
})();
</script>
