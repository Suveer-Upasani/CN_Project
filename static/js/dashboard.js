/**
 * PortSentinel Dashboard Controller
 * Handles target scan dispatch, form validation, and live progress polling.
 */

document.addEventListener('DOMContentLoaded', () => {
  const scanForm = document.getElementById('scan-form');
  const targetInput = document.getElementById('target-input');
  const portsInput = document.getElementById('ports-input');
  const authCheckbox = document.getElementById('auth-confirm');
  const startBtn = document.getElementById('start-scan-btn');
  const errorBox = document.getElementById('form-error');

  const liveContainer = document.getElementById('live-scan-container');
  const livePhaseText = document.getElementById('live-phase-text');
  const liveStatusBadge = document.getElementById('live-status-badge');
  const liveTargetDisplay = document.getElementById('live-target-display');
  const liveIpDisplay = document.getElementById('live-ip-display');
  const liveElapsedDisplay = document.getElementById('live-elapsed-display');
  const liveDetailsLink = document.getElementById('live-details-link');
  const scanSpinner = document.getElementById('scan-spinner');

  let activePollInterval = null;

  if (!scanForm) return;

  function showError(msg) {
    if (!errorBox) return;
    errorBox.textContent = msg;
    errorBox.style.display = 'block';
  }

  function hideError() {
    if (!errorBox) return;
    errorBox.textContent = '';
    errorBox.style.display = 'none';
  }

  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const targetVal = targetInput.value.trim();
    const portsVal = portsInput.value.trim();
    const isAuthorized = authCheckbox.checked;

    // Client-side validations
    if (!targetVal) {
      showError('Target IP address or hostname is required.');
      targetInput.focus();
      return;
    }

    if (!isAuthorized) {
      showError('You must confirm authorization to scan this host.');
      authCheckbox.focus();
      return;
    }

    // Set UI loading state
    startBtn.disabled = true;
    startBtn.innerHTML = `
      <span class="spinner" style="width: 14px; height: 14px; margin-right: 6px;"></span>
      <span>Submitting Scan...</span>
    `;

    try {
      const csrfToken = window.getCSRFToken ? window.getCSRFToken() : '';
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          target: targetVal,
          ports: portsVal || null,
          authorized: isAuthorized,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Scan submission failed (${response.status})`);
      }

      // Success: display live scan box
      startBtn.innerHTML = `
        <polygon points="5 3 19 12 5 21 5 3"/>
        <span>Scan In Progress</span>
      `;

      liveTargetDisplay.textContent = data.target;
      liveIpDisplay.textContent = data.resolved_ip || data.target;
      livePhaseText.textContent = 'Scan queued...';
      liveStatusBadge.textContent = 'QUEUED';
      liveStatusBadge.className = 'badge badge-queued';
      liveDetailsLink.href = data.details_url;
      liveContainer.style.display = 'flex';

      // Start live polling
      startPollingScan(data.scan_id);

    } catch (err) {
      showError(err.message || 'An unexpected error occurred while starting the scan.');
      resetSubmitButton();
    }
  });

  function resetSubmitButton() {
    startBtn.disabled = false;
    startBtn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      <span>Start Scan</span>
    `;
  }

  function startPollingScan(scanId) {
    if (activePollInterval) {
      clearInterval(activePollInterval);
    }

    activePollInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}/status`);
        if (!res.ok) {
          throw new Error('Failed to query scan status.');
        }

        const statusData = await res.json();

        livePhaseText.textContent = statusData.current_phase || 'Scanning...';
        liveElapsedDisplay.textContent = `${statusData.elapsed_seconds.toFixed(1)}s`;

        if (statusData.status === 'running') {
          liveStatusBadge.textContent = 'RUNNING';
          liveStatusBadge.className = 'badge badge-running';
        } else if (statusData.status === 'completed') {
          liveStatusBadge.textContent = 'COMPLETED';
          liveStatusBadge.className = 'badge badge-up';
          livePhaseText.textContent = 'Scan completed successfully!';
          if (scanSpinner) scanSpinner.style.display = 'none';

          clearInterval(activePollInterval);
          resetSubmitButton();

          // Refresh recent scans table after completion
          refreshRecentScans();
        } else if (statusData.status === 'failed') {
          liveStatusBadge.textContent = 'FAILED';
          liveStatusBadge.className = 'badge badge-failed';
          livePhaseText.textContent = statusData.error_message || 'Scan failed.';
          if (scanSpinner) scanSpinner.style.display = 'none';

          clearInterval(activePollInterval);
          resetSubmitButton();
          refreshRecentScans();
        }

      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 1500);
  }

  async function refreshRecentScans() {
    try {
      const res = await fetch('/api/scans?limit=6');
      if (!res.ok) return;
      const data = await res.json();
      const scans = data.scans || [];
      const tbody = document.getElementById('recent-scans-tbody');
      if (!tbody || scans.length === 0) return;

      tbody.innerHTML = scans.map(s => `
        <tr>
          <td><strong class="mono-cell">${escapeHtml(s.target)}</strong></td>
          <td class="mono-cell text-muted">${escapeHtml(s.resolved_ip || '-')}</td>
          <td>
            ${s.status === 'completed' 
              ? (s.host_status === 'up' ? '<span class="badge badge-up">UP</span>' : `<span class="badge badge-down">${escapeHtml(s.host_status.toUpperCase())}</span>`)
              : `<span class="badge badge-${s.status}">${escapeHtml(s.status.toUpperCase())}</span>`
            }
          </td>
          <td>
            ${s.status === 'completed' && s.host_status === 'up'
              ? `<span class="badge badge-category" style="color: var(--accent-cyan); font-weight: 700;">${s.open_ports_count}</span>`
              : '<span class="text-dim">-</span>'
            }
          </td>
          <td class="mono-cell">${s.duration.toFixed(1)}s</td>
          <td class="text-muted" style="font-size: 12px;">${escapeHtml(s.created_at)}</td>
          <td>
            <a href="/scans/${s.scan_id}" class="btn btn-secondary btn-sm" style="padding: 4px 10px;">Inspect</a>
          </td>
        </tr>
      `).join('');

      // Also refresh metrics
      const metricsRes = await fetch('/api/metrics');
      if (metricsRes.ok) {
        const m = await metricsRes.json();
        // Update metric values in the DOM if matching elements exist
      }
    } catch (e) {
      console.warn('Unable to refresh recent scans:', e);
    }
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
