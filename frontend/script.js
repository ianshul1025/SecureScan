const scanButton = document.getElementById('scanButton');
const urlInput = document.getElementById('urlInput');
const scanProfileSelect = document.getElementById('scanProfileSelect');
const profileNotice = document.getElementById('profileNotice');
const scanSpinner = document.getElementById('scanSpinner');
const scanButtonText = document.getElementById('scanButtonText');
const loadingStatus = document.getElementById('loadingStatus');
const feedback = document.getElementById('feedback');

const resultCard = document.getElementById('resultCard');
const resultSummary = document.getElementById('resultSummary');
const overallRiskBadge = document.getElementById('overallRiskBadge');
const hostDetails = document.getElementById('hostDetails');
const openPortsSection = document.getElementById('openPortsSection');
const recommendationsSection = document.getElementById('recommendationsSection');

document.documentElement.classList.add('js');
setupRevealObserver();

function setupRevealObserver() {
    const revealItems = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window)) {
        revealItems.forEach(item => item.classList.add('visible'));
        return;
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const delay = Number(entry.target.dataset.revealDelay || 0);
                entry.target.style.transitionDelay = `${delay}ms`;
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15 });

    revealItems.forEach(item => observer.observe(item));
}

scanProfileSelect.addEventListener('change', updateProfileNotice);
updateProfileNotice();

function updateProfileNotice() {
    const selected = scanProfileSelect.value;
    profileNotice.classList.add('d-none');
    profileNotice.className = 'profile-notice mb-4 d-none';
    profileNotice.innerHTML = '';

    const infoSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`;
    const alertSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`;

    if (selected === 'DETAILED') {
        profileNotice.classList.remove('d-none');
        profileNotice.classList.add('notice-info');
        profileNotice.innerHTML = `
            <span class="notice-icon">${infoSvg}</span>
            <div>
                <strong>Detailed Service Detection</strong><br>
                <span>Additional service and version detection may increase assessment execution time.</span>
            </div>`;
    } else if (selected === 'FULL') {
        profileNotice.classList.remove('d-none');
        profileNotice.classList.add('notice-warning');
        profileNotice.innerHTML = `
            <span class="notice-icon">${alertSvg}</span>
            <div>
                <strong>Full Port Scan Notice</strong><br>
                <span>Full port scans inspect all TCP ports and may take significantly longer to complete.</span>
            </div>`;
    } else if (selected === 'OS') {
        profileNotice.classList.remove('d-none');
        profileNotice.classList.add('notice-info');
        profileNotice.innerHTML = `
            <span class="notice-icon">${infoSvg}</span>
            <div>
                <strong>Operating System Fingerprinting Notice</strong><br>
                <span>Operating system detection depends on target responses, network conditions, and available privileges.</span>
            </div>`;
    } else if (selected === 'AGGRESSIVE') {
        profileNotice.classList.remove('d-none');
        profileNotice.classList.add('notice-warning');
        profileNotice.innerHTML = `
            <span class="notice-icon">${alertSvg}</span>
            <div>
                <strong>Aggressive Assessment Notice</strong><br>
                <span>Aggressive scans perform additional service, OS, script, and traceroute analysis and may take longer to complete.</span>
            </div>`;
    }
}

scanButton.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    const scanProfile = scanProfileSelect.value;

    clearFeedback();
    hideResult();

    if (!url) {
        showFeedback('Please enter a valid website URL.', 'danger');
        urlInput.focus();
        return;
    }

    setLoading(true, scanProfile);

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, scanProfile })
        });

        const payload = await response.json();
        if (!payload.success) {
            showFeedback(payload.message || 'Security assessment failed', 'danger');
            renderFailedState(payload.message || 'The assessment could not be completed because of a technical error.');
        } else {
            renderResults(payload.data);
        }
    } catch (error) {
        showFeedback('Unable to complete assessment. Please check network connectivity or backend server.', 'danger');
        renderFailedState('Unable to communicate with SecureScan server. Verify server execution.');
    } finally {
        setLoading(false);
    }
});

function setLoading(isLoading, profile = 'QUICK') {
    scanButton.disabled = isLoading;
    scanButton.setAttribute('aria-busy', isLoading.toString());
    scanSpinner.classList.toggle('d-none', !isLoading);
    scanButtonText.textContent = isLoading ? 'Analyzing Target...' : 'Analyze Website';

    if (isLoading) {
        scanButton.classList.add('loading');
        let statusText = 'Preparing Assessment · Resolving Target · Running Quick Scan · Analyzing Findings · Generating Report';

        if (profile === 'DETAILED') {
            statusText = 'Preparing Assessment · Resolving Target · Discovering Services & Versions · Analyzing Findings · Generating Report';
        } else if (profile === 'FULL') {
            statusText = 'Preparing Assessment · Resolving Target · Scanning All TCP Ports · Analyzing Findings · Generating Report';
        } else if (profile === 'OS') {
            statusText = 'Preparing Assessment · Resolving Target · Fingerprinting Operating System · Analyzing Findings · Generating Report';
        } else if (profile === 'AGGRESSIVE') {
            statusText = 'Preparing Assessment · Resolving Target · Executing Advanced Reconnaissance · Analyzing Findings · Generating Report';
        }

        loadingStatus.textContent = statusText;
    } else {
        scanButton.classList.remove('loading');
        loadingStatus.textContent = '';
    }
}

function showFeedback(message, type) {
    feedback.innerHTML = `<div class="alert alert-${type} mb-0 shadow-sm" role="alert">${escapeHtml(message)}</div>`;
}

function clearFeedback() {
    feedback.innerHTML = '';
}

function hideResult() {
    resultCard.classList.add('d-none');
}

function renderResults(data) {
    resultCard.classList.remove('d-none');

    const assessmentStatus = data.assessmentStatus || 'COMPLETED';
    const riskLevel = data.riskAnalysis ? data.riskAnalysis.riskLevel : 'LOW';
    const openPorts = data.openPorts || [];

    // State C: INCONCLUSIVE ASSESSMENT
    if (assessmentStatus === 'INCONCLUSIVE' || riskLevel === 'INCONCLUSIVE' || data.hostStatus === 'UNKNOWN') {
        renderInconclusiveState(data);
        return;
    }

    // State B: COMPLETED SCAN WITH ZERO OPEN PORTS
    if (openPorts.length === 0) {
        renderZeroPortsState(data);
        return;
    }

    // State A: COMPLETED SCAN WITH DISCOVERED PORTS
    renderPortsDiscoveredState(data);
}

function renderPortsDiscoveredState(data) {
    const riskLevel = data.riskAnalysis ? data.riskAnalysis.riskLevel : 'LOW';
    let badgeClass = 'badge-risk-low';
    if (riskLevel === 'MEDIUM') badgeClass = 'badge-risk-medium';
    if (riskLevel === 'HIGH') badgeClass = 'badge-risk-high';

    overallRiskBadge.innerHTML = `<span class="badge-risk ${badgeClass}">${escapeHtml(riskLevel)} RISK</span>`;
    resultSummary.innerHTML = `<p class="mb-0">${escapeHtml(data.riskAnalysis ? data.riskAnalysis.summary : 'Assessment completed.')}</p>`;

    renderMetadataGrid(data);

    const rows = data.openPorts.map(port => {
        const versionStr = (port.version && port.version.trim() !== '') ? port.version : '—';
        return `
            <tr>
                <td><strong>${port.port}</strong></td>
                <td>${escapeHtml(port.protocol)}</td>
                <td><span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25 px-2 py-1">${escapeHtml(port.state)}</span></td>
                <td>${escapeHtml(port.service)}</td>
                <td>${escapeHtml(versionStr)}</td>
            </tr>`;
    }).join('');

    openPortsSection.innerHTML = `
        <h4 class="section-label mb-3">DISCOVERED NETWORK SERVICES</h4>
        <div class="table-responsive">
            <table class="table-dark-custom">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
        </div>`;

    renderRecommendations(data.riskAnalysis ? data.riskAnalysis.recommendations : []);
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderZeroPortsState(data) {
    overallRiskBadge.innerHTML = `<span class="badge-risk badge-risk-low">LOW RISK</span>`;
    resultSummary.innerHTML = `<p class="mb-0">${escapeHtml(data.riskAnalysis ? data.riskAnalysis.summary : 'Security assessment completed with zero open ports discovered.')}</p>`;

    renderMetadataGrid(data);

    openPortsSection.innerHTML = `
        <div class="no-ports-card">
            <h4 class="h5 fw-bold mb-2">NO OPEN PORTS DETECTED</h4>
            <p class="mb-0">No open ports were identified within the scope of this scan. This result reflects the selected scan profile and observed network conditions and should not be interpreted as proof that the target is free from vulnerabilities or other security risks.</p>
        </div>`;

    renderRecommendations(data.riskAnalysis ? data.riskAnalysis.recommendations : [
        "No exposed services were identified during this assessment. Continue maintaining secure configurations, applying security updates, and restricting unnecessary network exposure."
    ]);
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderInconclusiveState(data) {
    overallRiskBadge.innerHTML = `<span class="badge-risk badge-risk-inconclusive">INCONCLUSIVE</span>`;
    resultSummary.innerHTML = `<p class="mb-0">${escapeHtml(data.riskAnalysis ? data.riskAnalysis.summary : 'Assessment inconclusive.')}</p>`;

    renderMetadataGrid(data);

    openPortsSection.innerHTML = `
        <div class="inconclusive-card">
            <h4 class="h5 fw-bold mb-2">ASSESSMENT INCONCLUSIVE</h4>
            <p class="mb-0">SecureScan could not obtain sufficient network information to determine the target's exposure. Network filtering, firewall rules, proxy/CDN infrastructure, target configuration, or connectivity conditions may affect scan results.</p>
        </div>`;

    renderRecommendations(data.riskAnalysis ? data.riskAnalysis.recommendations : [
        "Verify network access controls and host reachability for the target hostname.",
        "Consider re-assessing using a different scan profile or validating target firewall configurations."
    ]);
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderFailedState(errorMessage) {
    resultCard.classList.remove('d-none');
    overallRiskBadge.innerHTML = `<span class="badge-risk badge-risk-failed">FAILED</span>`;
    resultSummary.innerHTML = `<p class="mb-0">Assessment could not be completed.</p>`;
    hostDetails.innerHTML = '';

    openPortsSection.innerHTML = `
        <div class="failed-card">
            <h4 class="h5 fw-bold mb-2">ASSESSMENT FAILED</h4>
            <p class="mb-0">${escapeHtml(errorMessage)}</p>
        </div>`;

    recommendationsSection.innerHTML = '';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderMetadataGrid(data) {
    const formattedDuration = data.scanDurationSeconds ? data.scanDurationSeconds.toFixed(2) + ' seconds' : '—';
    const formattedTimestamp = data.scanTimestamp ? new Date(data.scanTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
    const profileTitle = data.scanProfileLabel || getProfileLabel(data.scanProfile);
    const assessmentStatusTitle = getAssessmentStatusTitle(data);

    hostDetails.innerHTML = `
        <div class="meta-card">
            <div class="meta-label">TARGET HOSTNAME</div>
            <div class="meta-value">${escapeHtml(data.host || 'Unknown')}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">IP ADDRESS</div>
            <div class="meta-value">${escapeHtml(data.ipAddress || 'Not available')}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">HOST STATUS</div>
            <div class="meta-value">${escapeHtml(data.hostStatus || 'UNKNOWN')}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">SCAN PROFILE</div>
            <div class="meta-value">${escapeHtml(profileTitle)}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">SCAN DURATION</div>
            <div class="meta-value">${escapeHtml(formattedDuration)}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">OPERATING SYSTEM</div>
            <div class="meta-value">${escapeHtml(data.os || 'Not scanned')}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">OPEN PORTS COUNT</div>
            <div class="meta-value">${data.openPorts ? data.openPorts.length : 0}</div>
        </div>
        <div class="meta-card">
            <div class="meta-label">ASSESSMENT STATUS</div>
            <div class="meta-value">${escapeHtml(assessmentStatusTitle)}</div>
        </div>`;
}

function getAssessmentStatusTitle(data) {
    const status = data.assessmentStatus;
    const risk = data.riskAnalysis ? data.riskAnalysis.riskLevel : '';
    if (status === 'INCONCLUSIVE' || risk === 'INCONCLUSIVE' || data.hostStatus === 'UNKNOWN') {
        return 'Inconclusive';
    }
    if (status === 'FAILED') {
        return 'Failed';
    }
    return 'Completed';
}

function renderRecommendations(recommendations) {
    if (recommendations && recommendations.length > 0) {
        const recList = recommendations.map(rec => `<li class="recommendation-item">${escapeHtml(rec)}</li>`).join('');
        recommendationsSection.innerHTML = `
            <h4 class="section-label mb-3">SECURITY RECOMMENDATIONS</h4>
            <ul class="recommendation-list">
                ${recList}
            </ul>`;
    } else {
        recommendationsSection.innerHTML = '';
    }
}

function getProfileLabel(profile) {
    switch (profile) {
        case 'DETAILED': return 'Detailed Scan';
        case 'FULL': return 'Full Port Scan';
        case 'OS': return 'OS Detection';
        case 'AGGRESSIVE': return 'Aggressive Scan';
        case 'QUICK':
        default: return 'Quick Scan';
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
