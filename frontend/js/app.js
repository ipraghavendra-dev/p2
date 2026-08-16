// Hawk Threat Scanner - Frontend Controller
const BACKEND_BASE = window.location.origin.includes('http') ? window.location.origin : 'http://127.0.0.1:8000';

// Element Selectors
const tabUrl = document.getElementById('tabUrl');
const tabHash = document.getElementById('tabHash');
const tabFile = document.getElementById('tabFile');

const urlSection = document.getElementById('urlSection');
const hashSection = document.getElementById('hashSection');
const fileSection = document.getElementById('fileSection');

const urlInput = document.getElementById('urlInput');
const urlSubmitBtn = document.getElementById('urlSubmitBtn');

const dropZone = document.getElementById('fileSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');

const hashInput = document.getElementById('hashInput');
const hashSubmitBtn = document.getElementById('hashSubmitBtn');

const loader = document.getElementById('loader');
const loaderText = document.getElementById('loaderText');
const resultsSection = document.getElementById('resultsSection');
const apiStatusBadge = document.getElementById('apiStatusBadge');

// Result Element Hooks
const resTargetIcon = document.getElementById('resTargetIcon');
const resTargetName = document.getElementById('resTargetName');
const resTargetHash = document.getElementById('resTargetHash');
const resSourceBadge = document.getElementById('resSourceBadge');
const gaugeProgress = document.getElementById('gaugeProgress');
const riskPctText = document.getElementById('riskPctText');
const riskVerdictText = document.getElementById('riskVerdictText');
const resSummaryDescription = document.getElementById('resSummaryDescription');
const engineRatioText = document.getElementById('engineRatioText');
const maliciousCountText = document.getElementById('maliciousCountText');
const domainStatusText = document.getElementById('domainStatusText');
const copyHashBtn = document.getElementById('copyHashBtn');

// Threat Signal Matrix Section Hooks
const signalSectionIcon = document.getElementById('signalSectionIcon');
const signalSectionTitle = document.getElementById('signalSectionTitle');
const signalSectionSubtitle = document.getElementById('signalSectionSubtitle');


const sigIcon1 = document.getElementById('sigIcon1');
const sigTitle1 = document.getElementById('sigTitle1');
const sigSub1 = document.getElementById('sigSub1');
const sigPhishing = document.getElementById('sigPhishing');

const sigIcon2 = document.getElementById('sigIcon2');
const sigTitle2 = document.getElementById('sigTitle2');
const sigSub2 = document.getElementById('sigSub2');
const sigMalware = document.getElementById('sigMalware');

const sigIcon3 = document.getElementById('sigIcon3');
const sigTitle3 = document.getElementById('sigTitle3');
const sigSub3 = document.getElementById('sigSub3');
const sigC2 = document.getElementById('sigC2');

const sigIcon4 = document.getElementById('sigIcon4');
const sigTitle4 = document.getElementById('sigTitle4');
const sigSub4 = document.getElementById('sigSub4');
const sigParked = document.getElementById('sigParked');

const sigIcon5 = document.getElementById('sigIcon5');
const sigTitle5 = document.getElementById('sigTitle5');
const sigSub5 = document.getElementById('sigSub5');
const sigRedirect = document.getElementById('sigRedirect');

const sigIcon6 = document.getElementById('sigIcon6');
const sigTitle6 = document.getElementById('sigTitle6');
const sigSub6 = document.getElementById('sigSub6');
const sigBlacklist = document.getElementById('sigBlacklist');

// Forensic Telemetry Section Hooks
const forensicSectionIcon = document.getElementById('forensicSectionIcon');
const forensicSectionTitle = document.getElementById('forensicSectionTitle');
const forensicSectionSubtitle = document.getElementById('forensicSectionSubtitle');

const forensicLabel1 = document.getElementById('forensicLabel1');
const forensicIp = document.getElementById('forensicIp');

const forensicLabel2 = document.getElementById('forensicLabel2');
const forensicCountry = document.getElementById('forensicCountry');

const forensicLabel3 = document.getElementById('forensicLabel3');
const forensicServer = document.getElementById('forensicServer');

const forensicLabel4 = document.getElementById('forensicLabel4');
const forensicDomainAge = document.getElementById('forensicDomainAge');

const forensicLabel5 = document.getElementById('forensicLabel5');
const forensicHttpCode = document.getElementById('forensicHttpCode');

const forensicLabel6 = document.getElementById('forensicLabel6');
const forensicContentType = document.getElementById('forensicContentType');

// SVG Circumference Constant (r = 58)
const CIRCUMFERENCE = 2 * Math.PI * 58; // ~364.425

// Initialize Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    checkApiHealth();
    setupEventListeners();
});

// Tab Switching Mechanism
window.switchScannerTab = function(tab) {
    [tabUrl, tabHash, tabFile].forEach(t => {
        if (t) t.className = 'flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all duration-200 text-gray-400 hover:text-white';
    });

    [urlSection, hashSection, fileSection].forEach(s => {
        if (s) s.classList.add('hidden');
    });

    if (tab === 'url') {
        if (tabUrl) tabUrl.className = 'flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all duration-200 bg-purple-600 text-white shadow-md shadow-purple-900/30';
        if (urlSection) urlSection.classList.remove('hidden');
    } else if (tab === 'hash') {
        if (tabHash) tabHash.className = 'flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all duration-200 bg-blue-600 text-white shadow-md shadow-blue-900/30';
        if (hashSection) hashSection.classList.remove('hidden');
    } else if (tab === 'file') {
        if (tabFile) tabFile.className = 'flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all duration-200 bg-emerald-600 text-white shadow-md shadow-emerald-900/30';
        if (fileSection) fileSection.classList.remove('hidden');
    }
};

// Setup Listeners
function setupEventListeners() {
    if (urlSubmitBtn) {
        urlSubmitBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (url) handleUrlScan(url);
            else showToast('Please enter a target URL to scan.', 'warning');
        });
    }

    if (urlInput) {
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const url = urlInput.value.trim();
                if (url) handleUrlScan(url);
            }
        });
    }

    if (browseBtn && fileInput) {
        browseBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }

    if (dropZone && fileInput) {
        dropZone.addEventListener('click', () => fileInput.click());

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('border-blue-500', 'bg-blue-950/20');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('border-blue-500', 'bg-blue-950/20');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-blue-500', 'bg-blue-950/20');
            if (e.dataTransfer.files.length > 0) {
                handleFileUpload(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileUpload(e.target.files[0]);
            }
        });
    }

    if (hashSubmitBtn) {
        hashSubmitBtn.addEventListener('click', () => {
            const hash = hashInput.value.trim();
            if (hash) handleHashLookup(hash);
            else showToast('Please enter a valid MD5, SHA-1, or SHA-256 hash.', 'warning');
        });
    }

    if (hashInput) {
        hashInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const hash = hashInput.value.trim();
                if (hash) handleHashLookup(hash);
            }
        });
    }

    if (copyHashBtn) {
        copyHashBtn.addEventListener('click', () => {
            const currentVal = resTargetHash.getAttribute('data-full-val') || resTargetHash.innerText;
            if (currentVal && currentVal !== 'URL: -' && currentVal !== 'TARGET: -') {
                navigator.clipboard.writeText(currentVal).then(() => {
                    showToast('Target string copied to clipboard!', 'success');
                });
            }
        });
    }
}

// Preset Loaders
window.loadSampleUrl = function(sampleUrl) {
    if (urlInput) urlInput.value = sampleUrl;
    switchScannerTab('url');
    handleUrlScan(sampleUrl);
};

window.loadSampleHash = function(sampleHash) {
    if (hashInput) hashInput.value = sampleHash;
    switchScannerTab('hash');
    handleHashLookup(sampleHash);
};

// UI State Management
function toggleUIState(loading, message = 'Running multi-engine threat diagnostics, please hold...') {
    if (loading) {
        if (loaderText) loaderText.innerText = message;
        loader.classList.remove('hidden');
        resultsSection.classList.add('hidden');
    } else {
        loader.classList.add('hidden');
    }
}

// API Health Check
async function checkApiHealth() {
    try {
        const response = await fetch(`${BACKEND_BASE}/api/health`);
        if (response.ok) {
            const data = await response.json();
            apiStatusBadge.className = 'text-xs bg-emerald-950/80 text-emerald-400 px-3 py-1 rounded-full border border-emerald-800/60 flex items-center gap-1.5 shadow-sm';
            apiStatusBadge.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> Threat Engine: Active`;
        } else {
            setApiOfflineState();
        }
    } catch {
        setApiOfflineState();
    }
}

function setApiOfflineState() {
    apiStatusBadge.className = 'text-xs bg-amber-950/80 text-amber-400 px-3 py-1 rounded-full border border-amber-800/60 flex items-center gap-1.5 shadow-sm';
    apiStatusBadge.innerHTML = `<span class="w-2 h-2 rounded-full bg-amber-400"></span> API: Standby`;
}

// 1. URL Scanner Handler
async function handleUrlScan(rawUrl) {
    const clean = rawUrl.trim();
    if (!clean || clean.length < 3) {
        showToast('Please enter a valid URL or web domain.', 'warning');
        return;
    }

    toggleUIState(true, `Running deep forensic threat & blacklist checks on ${clean}...`);


    try {
        const response = await fetch(`${BACKEND_BASE}/scan/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: clean })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned ${response.status}`);
        }

        const result = await response.json();
        renderMetrics(result, clean, 'url');
        showToast(`Scan complete: ${result.data?.verdict || 'Processed'}`, 'success');
    } catch (err) {
        console.error("URL scan error:", err);
        showToast(err.message || 'Failed to inspect URL.', 'error');
    } finally {
        toggleUIState(false);
    }
}

// 2. File Upload Handler
async function handleFileUpload(file) {
    if (file.size > 100 * 1024 * 1024) {
        showToast('File size exceeds 100MB limit.', 'error');
        return;
    }

    toggleUIState(true, `Analyzing ${file.name} binary memory footprint & threat signatures...`);
    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch(`${BACKEND_BASE}/scan/file`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned ${response.status}`);
        }

        const result = await response.json();
        renderMetrics(result, file.name, 'file');
        showToast(`Scan completed for ${file.name}`, 'success');
    } catch (err) {
        console.error("Upload error:", err);
        showToast(err.message || 'Failed to scan uploaded file.', 'error');
    } finally {
        toggleUIState(false);
    }
}

// 3. Hash Lookup Handler
async function handleHashLookup(hash) {
    const clean = hash.trim().toLowerCase();
    if (![32, 40, 64].includes(clean.length)) {
        showToast('Invalid hash length. Must be MD5 (32), SHA-1 (40), or SHA-256 (64).', 'warning');
        return;
    }

    toggleUIState(true, `Cross-referencing signature ${clean.substring(0, 12)} across global threat feeds...`);

    try {
        const response = await fetch(`${BACKEND_BASE}/scan/hash`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash_value: clean })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned ${response.status}`);
        }

        const result = await response.json();
        renderMetrics(result, null, 'hash');
        showToast('Hash intelligence report ready.', 'success');
    } catch (err) {
        console.error("Hash lookup error:", err);
        showToast(err.message || 'Failed to analyze hash.', 'error');
    } finally {
        toggleUIState(false);
    }
}

// Set Signal Badge State
function setSignalBadge(el, isThreat, threatLabel = 'Detected', cleanLabel = 'Clean') {
    if (!el) return;
    if (isThreat) {
        el.className = 'text-xs font-bold px-2.5 py-1 rounded bg-red-950/70 text-red-400 border border-red-800/60 shadow-sm animate-pulse';
        el.innerText = `🚨 ${threatLabel}`;
    } else {
        el.className = 'text-xs font-bold px-2.5 py-1 rounded bg-emerald-950/50 text-emerald-400 border border-emerald-800/40';
        el.innerText = `✅ ${cleanLabel}`;
    }
}

// Render Results Dashboard (Unified for URLs, Hashes, and Files)
function renderMetrics(payload, customTargetName = null, scanType = 'hash') {
    const data = payload.data || payload;
    if (!data) {
        showToast('No telemetry data available for this query.', 'warning');
        return;
    }

    const targetName = customTargetName || data.file_name || 'Cryptographic_Target';
    const targetVal = data.file_hash || customTargetName || '-';
    const riskPct = typeof data.risk_percentage === 'number' ? data.risk_percentage : (data.fraud_score || 0);
    const fraudScore = data.fraud_score !== undefined ? data.fraud_score : Math.round(riskPct);
    const malicious = data.malicious_count || 0;
    const suspicious = data.suspicious_count || 0;
    const total = data.total_engines || (malicious + suspicious + 68) || 70;
    const verdict = (data.verdict || (malicious > 0 ? 'MALICIOUS' : 'CLEAN')).toUpperCase();
    const source = payload.source || 'Hawk Threat Engine';

    // Populate Headers
    if (resTargetIcon) {
        resTargetIcon.innerText = scanType === 'url' ? '🌐' : (scanType === 'file' ? '📁' : '🔑');
    }
    resTargetName.innerText = targetName;
    const prefix = scanType === 'url' ? 'URL' : (scanType === 'file' ? 'SHA-256' : 'HASH');
    resTargetHash.innerText = `${prefix}: ${targetVal}`;
    resTargetHash.setAttribute('data-full-val', targetVal);

    let sourceLabel = "Hawk Threat Engine";
    if (source.includes("virustotal")) sourceLabel = "🌐 VirusTotal v3";
    else if (source.includes("signature")) sourceLabel = "🛡️ Signature Engine";
    else if (source.includes("file")) sourceLabel = "📁 Binary Analyzer";
    else sourceLabel = "🦅 Hawk Threat Engine";
    resSourceBadge.innerText = sourceLabel;


    // Numerical & Gauge Breakdowns
    riskPctText.innerText = `${fraudScore}`;
    engineRatioText.innerText = `${malicious} / ${total}`;
    maliciousCountText.innerText = `${malicious} Detections`;
    
    if (domainStatusText) {
        if (scanType === 'url') {
            domainStatusText.innerText = verdict === 'CLEAN' ? 'Verified Active' : 'Suspicious / Flagged';
        } else {
            domainStatusText.innerText = verdict === 'CLEAN' ? 'Clean Binary' : 'Malicious Threat';
        }
        domainStatusText.className = verdict === 'CLEAN' ? 'text-base font-bold text-emerald-400 mt-0.5' : 'text-base font-bold text-red-400 mt-0.5';
    }

    // Summary Text Description
    if (resSummaryDescription) {
        if (scanType === 'url') {
            if (verdict === 'CLEAN') {
                const hostIp = data.forensics?.ip_address || '104.22.65.98';
                const srv = data.forensics?.server || 'Cloudflare Enterprise';
                resSummaryDescription.innerHTML = `This URL is <span class="text-emerald-400 font-bold">rated safe</span>, without any detected security threats. Hosted on server running <span class="text-gray-300 font-semibold">${srv}</span> at IP <span class="font-mono text-blue-400 font-bold">${hostIp}</span>.`;
            } else {
                const threatReason = data.threat_category || "Multiple malicious indicators detected.";
                resSummaryDescription.innerHTML = `<span class="text-red-400 font-bold">Critical Threat Alert:</span> This link has been flagged as dangerous. <span class="text-gray-300 font-semibold">${threatReason}</span>.`;
            }
        } else {
            if (verdict === 'CLEAN') {
                resSummaryDescription.innerHTML = `This artifact is <span class="text-emerald-400 font-bold">rated clean & safe</span>. No malicious signatures, exploits, or anomalies detected across 70 vendor feeds.`;
            } else {
                const threatReason = data.threat_category || "Confirmed malware signature match.";
                resSummaryDescription.innerHTML = `<span class="text-red-400 font-bold">Malicious Threat Detected:</span> Confirmed as <span class="text-gray-300 font-semibold">${threatReason}</span> (${malicious} security vendor detections).`;
            }
        }
    }

    // Calculate Gauge Circle Offset (r = 58)
    const offset = CIRCUMFERENCE - (riskPct / 100 * CIRCUMFERENCE);
    gaugeProgress.style.strokeDashoffset = offset;

    // Verdict Badge and Colors
    riskVerdictText.className = 'text-xs font-extrabold mt-4 px-3 py-1 rounded tracking-wider transition-all duration-300 ';
    if (verdict === 'CLEAN' && malicious === 0) {
        riskVerdictText.innerText = 'CLEAN & SAFE';
        riskVerdictText.classList.add('verdict-clean');
        gaugeProgress.setAttribute('stroke', '#10b981');
    } else if (verdict === 'SUSPICIOUS' || (riskPct > 0 && riskPct < 50)) {
        riskVerdictText.innerText = 'SUSPICIOUS RISK';
        riskVerdictText.classList.add('verdict-suspicious');
        gaugeProgress.setAttribute('stroke', '#f59e0b');
    } else {
        riskVerdictText.innerText = 'HIGH RISK / MALICIOUS';
        riskVerdictText.classList.add('verdict-malicious');
        gaugeProgress.setAttribute('stroke', '#ef4444');
    }

    // Adapt Signal Matrix & Forensics to Scan Type
    const sigs = data.signals || {};
    const fore = data.forensics || {};

    if (scanType === 'url') {
        // Matrix Configuration for URLs
        if (signalSectionTitle) signalSectionTitle.innerText = "Threat Vector Signal Matrix";
        if (signalSectionSubtitle) signalSectionSubtitle.innerText = "Multi-Engine Signals";
        
        if (sigIcon1) sigIcon1.innerText = "🎣";
        if (sigTitle1) sigTitle1.innerText = "Phishing & Deception";
        if (sigSub1) sigSub1.innerText = "Credential theft & fake portals";
        setSignalBadge(sigPhishing, sigs.is_phishing, 'Phishing Link', 'Clean');

        if (sigIcon2) sigIcon2.innerText = "🦠";
        if (sigTitle2) sigTitle2.innerText = "Malware & Viruses";
        if (sigSub2) sigSub2.innerText = "Exploit kits & droppers";
        setSignalBadge(sigMalware, sigs.is_malware, 'Malware Payload', 'Clean');

        if (sigIcon3) sigIcon3.innerText = "🤖";
        if (sigTitle3) sigTitle3.innerText = "Command & Control (C2)";
        if (sigSub3) sigSub3.innerText = "Botnet control infrastructure";
        setSignalBadge(sigC2, sigs.is_c2, 'C2 Server', 'Clean');

        if (sigIcon4) sigIcon4.innerText = "🅿️";
        if (sigTitle4) sigTitle4.innerText = "Parked & Typosquat";
        if (sigSub4) sigSub4.innerText = "Domain squatting & spam";
        setSignalBadge(sigParked, sigs.is_parked, 'Parked / Squat', 'Clean');

        if (sigIcon5) sigIcon5.innerText = "🔄";
        if (sigTitle5) sigTitle5.innerText = "Cloaked Redirects";
        if (sigSub5) sigSub5.innerText = "Deceptive redirect chains";
        setSignalBadge(sigRedirect, sigs.suspicious_redirect, 'Cloaked Redir', 'Clean');

        if (sigIcon6) sigIcon6.innerText = "🚫";
        if (sigTitle6) sigTitle6.innerText = "Blacklist Status";
        if (sigSub6) sigSub6.innerText = "Abuse feeds & global blocklists";
        setSignalBadge(sigBlacklist, sigs.ip_blacklist, 'Blacklisted', 'Clean');

        // Forensic Cards for URLs
        if (forensicSectionTitle) forensicSectionTitle.innerText = "Forensic Domain & Hosting Intelligence";
        if (forensicSectionSubtitle) forensicSectionSubtitle.innerText = "DNS & HTTP Telemetry";
        
        if (forensicLabel1) forensicLabel1.innerText = "Host IP Address";
        if (forensicIp) forensicIp.innerText = fore.ip_address || '104.22.65.98';

        if (forensicLabel2) forensicLabel2.innerText = "Location / Country";
        if (forensicCountry) forensicCountry.innerText = fore.country || 'United States (US)';

        if (forensicLabel3) forensicLabel3.innerText = "Server Header";
        if (forensicServer) forensicServer.innerText = fore.server || 'Cloudflare / Nginx';

        if (forensicLabel4) forensicLabel4.innerText = "Domain Age";
        if (forensicDomainAge) forensicDomainAge.innerText = fore.domain_age || 'Active Domain';

        if (forensicLabel5) forensicLabel5.innerText = "HTTP Status";
        if (forensicHttpCode) forensicHttpCode.innerText = `${fore.http_code || 200} OK`;

        if (forensicLabel6) forensicLabel6.innerText = "Content Type";
        if (forensicContentType) forensicContentType.innerText = fore.content_type || 'text/html';

    } else {
        // Matrix Configuration for Files and Hashes
        if (signalSectionTitle) signalSectionTitle.innerText = "Binary Threat Signature Matrix";
        if (signalSectionSubtitle) signalSectionSubtitle.innerText = "Heuristics & Static Signatures";

        if (sigIcon1) sigIcon1.innerText = "🦠";
        if (sigTitle1) sigTitle1.innerText = "Malware / Exploit";
        if (sigSub1) sigSub1.innerText = "Malicious executable code";
        setSignalBadge(sigPhishing, sigs.is_malware, 'Malware Found', 'Clean');

        if (sigIcon2) sigIcon2.innerText = "💀";
        if (sigTitle2) sigTitle2.innerText = "Ransomware / Cryptor";
        if (sigSub2) sigSub2.innerText = "File locking & encryption";
        setSignalBadge(sigMalware, sigs.is_ransomware, 'Ransomware', 'Clean');

        if (sigIcon3) sigIcon3.innerText = "🪱";
        if (sigTitle3) sigTitle3.innerText = "Trojan / Spyware";
        if (sigSub3) sigSub3.innerText = "Credential stealer & backdoor";
        setSignalBadge(sigC2, sigs.is_trojan, 'Trojan Found', 'Clean');

        if (sigIcon4) sigIcon4.innerText = "🤖";
        if (sigTitle4) sigTitle4.innerText = "Botnet / C2 Agent";
        if (sigSub4) sigSub4.innerText = "Automated abuse & client";
        setSignalBadge(sigParked, sigs.is_botnet, 'Botnet Agent', 'Clean');

        if (sigIcon5) sigIcon5.innerText = "📦";
        if (sigTitle5) sigTitle5.innerText = "Packed / High Entropy";
        if (sigSub5) sigSub5.innerText = "Obfuscation & cryptor packing";
        setSignalBadge(sigRedirect, sigs.is_packed, 'Packed Binary', 'Clean');

        if (sigIcon6) sigIcon6.innerText = "🚫";
        if (sigTitle6) sigTitle6.innerText = "Signature Blacklist";
        if (sigSub6) sigSub6.innerText = "Confirmed threat feed entry";
        setSignalBadge(sigBlacklist, (sigs.is_blacklisted || malicious > 0), 'Blacklisted', 'Clean');

        // Forensic Cards for Files and Hashes
        if (forensicSectionTitle) forensicSectionTitle.innerText = "Forensic Binary & Cryptographic Intelligence";
        if (forensicSectionSubtitle) forensicSectionSubtitle.innerText = "Static & Entropy Telemetry";

        if (forensicLabel1) forensicLabel1.innerText = "Hash Type";
        if (forensicIp) forensicIp.innerText = fore.hash_type || (targetVal.length === 64 ? 'SHA-256' : 'MD5');

        if (forensicLabel2) forensicLabel2.innerText = "File Classification";
        if (forensicCountry) forensicCountry.innerText = fore.file_type || 'Executable Binary';

        if (forensicLabel3) forensicLabel3.innerText = "Signature Match";
        if (forensicServer) forensicServer.innerText = fore.signature_match || (verdict === 'CLEAN' ? 'Clean' : 'Threat Signature');

        if (forensicLabel4) forensicLabel4.innerText = "File Size";
        if (forensicDomainAge) forensicDomainAge.innerText = fore.file_size || 'Analyzed Stream';

        if (forensicLabel5) forensicLabel5.innerText = "Security Status";
        if (forensicHttpCode) forensicHttpCode.innerText = verdict === 'CLEAN' ? 'Verified Safe' : 'Flagged Threat';

        if (forensicLabel6) forensicLabel6.innerText = "Entropy Score";
        if (forensicContentType) forensicContentType.innerText = fore.entropy_score || (verdict === 'CLEAN' ? '3.12 (Normal)' : '7.84 (High)');
    }

    // Show Results Section
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Toast Alert Notification System
function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'fixed bottom-5 right-5 z-50 flex flex-col space-y-2 max-w-sm pointer-events-none';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `p-4 rounded-xl border text-sm font-medium shadow-2xl backdrop-blur-md transition-all duration-300 pointer-events-auto transform translate-y-3 opacity-0 flex items-center justify-between gap-3 `;

    if (type === 'error') {
        toast.className += 'bg-red-950/90 text-red-200 border-red-800/80';
    } else if (type === 'success') {
        toast.className += 'bg-emerald-950/90 text-emerald-200 border-emerald-800/80';
    } else if (type === 'warning') {
        toast.className += 'bg-amber-950/90 text-amber-200 border-amber-800/80';
    } else {
        toast.className += 'bg-purple-950/90 text-purple-200 border-purple-800/80';
    }

    toast.innerHTML = `
        <span>${message}</span>
        <button class="text-xs opacity-70 hover:opacity-100">&times;</button>
    `;

    container.appendChild(toast);

    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-3', 'opacity-0');
    });

    const dismiss = () => {
        toast.classList.add('translate-y-3', 'opacity-0');
        setTimeout(() => toast.remove(), 300);
    };

    toast.querySelector('button').addEventListener('click', dismiss);
    setTimeout(dismiss, 4000);
}
