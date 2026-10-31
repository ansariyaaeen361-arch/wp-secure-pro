jQuery(document).ready(function($) {

    // Run Security Scan
    $('#swps-run-scan-btn').on('click', function() {
        var btn = $(this);
        btn.prop('disabled', true).html('<span class="dashicons dashicons-update-alt" style="animation:spin 1s linear infinite"></span> Scanning...');
        $('#swps-scan-progress').show();
        $('#swps-scan-result').hide();

        $.post(swps_vars.url, {
            action: 'swps_run_scan',
            nonce:  swps_vars.nonce
        }, function(response) {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-search"></span> Run Scan Now');
            $('#swps-scan-progress').hide();

            if (response.success) {
                var data     = response.data;
                var threats  = data.threats ? data.threats.length : 0;
                var color    = threats > 0 ? '#e74c3c' : '#27ae60';
                var icon     = threats > 0 ? '⚠️' : '✓';
                var html     = '<div class="swps-alert-inline" style="border-left:4px solid ' + color + ';background:' + (threats > 0 ? '#fde8e8' : '#d4edda') + ';color:' + color + '">';
                html        += icon + ' Scan complete: ' + data.scanned_files + ' files scanned, <strong>' + threats + ' threats</strong> found.</div>';

                if (threats > 0) {
                    html += '<p style="margin-top:10px;font-weight:600">Suspicious files:</p><ul>';
                    $.each(data.threats, function(i, t) {
                        html += '<li><code>' + t.file + '</code>: ' + t.threats.join(', ') + '</li>';
                    });
                    html += '</ul>';
                }

                $('#swps-scan-result').html(html).show();
            } else {
                $('#swps-scan-result').html('<div class="swps-alert-inline swps-critical">Scan failed. Please try again.</div>').show();
            }
        }).fail(function() {
            btn.prop('disabled', false).text('Run Scan Now');
            $('#swps-scan-progress').hide();
            $('#swps-scan-result').html('<div class="swps-alert-inline swps-critical">Request failed. Check your connection.</div>').show();
        });
    });

    // Block IP buttons
    $(document).on('click', '.swps-block-btn', function() {
        var ip  = $(this).data('ip');
        var btn = $(this);
        if (!ip) return;
        if (!confirm('Block IP address: ' + ip + '?')) return;

        $.post(swps_vars.url, {
            action: 'swps_block_ip',
            nonce:  swps_vars.nonce,
            ip:     ip,
            reason: 'Manual block from dashboard'
        }, function(response) {
            if (response.success) {
                btn.text('Blocked').css({background:'#c0392b',color:'#fff',cursor:'default'}).prop('disabled', true);
                showToast('IP ' + ip + ' has been blocked.', 'success');
            }
        });
    });

    // Clear log
    $('#swps-clear-log-btn').on('click', function() {
        if (!confirm('Clear all activity log entries? This cannot be undone.')) return;
        $.post(swps_vars.url, {
            action: 'swps_clear_log',
            nonce:  swps_vars.nonce
        }, function(response) {
            if (response.success) {
                location.reload();
            }
        });
    });

    // Toast notification
    function showToast(msg, type) {
        var color = type === 'success' ? '#27ae60' : '#e74c3c';
        var toast = $('<div>').text(msg).css({
            position: 'fixed', bottom: '24px', right: '24px',
            background: color, color: '#fff',
            padding: '12px 24px', borderRadius: '8px',
            boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
            zIndex: 99999, fontSize: '14px', fontWeight: '600'
        }).appendTo('body');
        setTimeout(function() { toast.fadeOut(400, function() { toast.remove(); }); }, 3000);
    }

    // Ensure unchecked swps_settings[...] checkboxes submit a 0 (otherwise an
    // unchecked box is simply absent and the toggle can never be turned OFF).
    $(document).on('submit', 'form', function() {
        var $f = $(this);
        $f.find('input[type=checkbox][name^="swps_settings["]').each(function() {
            if (!this.checked) {
                $('<input>', { type: 'hidden', name: this.name, value: '0' }).appendTo($f);
            }
        });
    });

    // CSS spin animation
    $('<style>@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }</style>').appendTo('head');
});
