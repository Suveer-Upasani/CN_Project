/**
 * PortSentinel Scan Details Controller
 * Handles live status polling for in-flight scans and table search/filtering/sorting.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Live status polling if scan is in-flight
  const pollingCard = document.getElementById('live-polling-card');
  if (pollingCard) {
    const scanId = pollingCard.getAttribute('data-scan-id');
    const phaseText = document.getElementById('scan-phase-text');
    const statusBadge = document.getElementById('scan-status-badge');
    const timerText = document.getElementById('scan-elapsed-timer');

    if (scanId) {
      const interval = setInterval(async () => {
        try {
          const res = await fetch(`/api/scans/${scanId}/status`);
          if (!res.ok) return;
          const data = await res.json();

          if (phaseText && data.current_phase) {
            phaseText.textContent = data.current_phase;
          }
          if (timerText && typeof data.elapsed_seconds === 'number') {
            timerText.textContent = `${data.elapsed_seconds.toFixed(1)}s`;
          }

          if (data.is_complete) {
            clearInterval(interval);
            if (statusBadge) {
              statusBadge.textContent = data.status.toUpperCase();
              statusBadge.className = data.status === 'completed' ? 'badge badge-up' : 'badge badge-failed';
            }
            if (phaseText) {
              phaseText.textContent = data.status === 'completed' ? 'Scan finished! Reloading results...' : 'Scan failed.';
            }
            // Auto reload after brief moment so full results and reports render
            setTimeout(() => {
              window.location.reload();
            }, 1000);
          }
        } catch (e) {
          console.warn('Status poll error:', e);
        }
      }, 1500);
    }
  }

  // 2. Interactive Ports Table Filtering
  const portSearch = document.getElementById('port-search');
  const categoryFilter = document.getElementById('category-filter');
  const portsTbody = document.getElementById('ports-tbody');

  function applyFilters() {
    if (!portsTbody) return;
    const query = portSearch ? portSearch.value.toLowerCase().trim() : '';
    const selectedCategory = categoryFilter ? categoryFilter.value : '';

    const rows = portsTbody.querySelectorAll('tr[data-category]');
    rows.forEach(row => {
      const rowText = row.textContent.toLowerCase();
      const rowCat = row.getAttribute('data-category') || '';

      const matchesSearch = !query || rowText.includes(query);
      const matchesCategory = !selectedCategory || rowCat === selectedCategory;

      row.style.display = (matchesSearch && matchesCategory) ? '' : 'none';
    });
  }

  if (portSearch) {
    portSearch.addEventListener('input', applyFilters);
  }
  if (categoryFilter) {
    categoryFilter.addEventListener('change', applyFilters);
  }

  // 3. Table Column Sorting
  const sortableHeaders = document.querySelectorAll('th.sortable');
  let currentSortCol = null;
  let sortAscending = true;

  sortableHeaders.forEach((th, colIdx) => {
    th.addEventListener('click', () => {
      if (!portsTbody) return;
      const sortType = th.getAttribute('data-sort') || 'string';
      const rows = Array.from(portsTbody.querySelectorAll('tr[data-port]'));

      if (currentSortCol === colIdx) {
        sortAscending = !sortAscending;
      } else {
        currentSortCol = colIdx;
        sortAscending = true;
      }

      rows.sort((a, b) => {
        const cellA = a.children[colIdx]?.textContent.trim() || '';
        const cellB = b.children[colIdx]?.textContent.trim() || '';

        if (sortType === 'int') {
          const numA = parseInt(cellA, 10) || 0;
          const numB = parseInt(cellB, 10) || 0;
          return sortAscending ? numA - numB : numB - numA;
        } else {
          return sortAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
        }
      });

      // Re-append sorted rows
      rows.forEach(r => portsTbody.appendChild(r));
    });
  });
});
