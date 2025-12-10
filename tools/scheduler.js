const cron = require('node-cron');
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');
const express = require('express');
const cors = require('cors');

// ============================================================================
// CONFIGURATION - Updated for ExiScale URL Health base
// ============================================================================

const AIRTABLE_CONFIG = {
    apiKey: 'patMUyJg0ED6dzx41.111935258c9b6eb1ec6af7d44487a2c83f13544b664ec225d3f6a590668aeab1',
    baseId: 'appZwri4LF6oF0QSB',
    baseUrl: 'https://api.airtable.com/v0/appZwri4LF6oF0QSB',
    tables: {
        users: 'Users',
        urls: 'URLs',
        scanLogs: 'ScanLogs',
        schedules: 'Schedules',
        detectionAlerts: 'DetectionAlerts',
        systemConfig: 'SystemConfig'
    }
};

const VIRUSTOTAL_API_KEY = '85ed39cad3d9d21180031bd74b408ea7036f55810eeeb13cfa4ac561c963d37e';
const API_BASE = 'https://www.virustotal.com/api/v3';
const POLL_INTERVAL = 5000; // 5 seconds
const MAX_ATTEMPTS = 30; // 2.5 minutes max wait
const DEFAULT_ALERT_INTERVAL_HOURS = 6;

// System config cache (loaded from Airtable)
let systemConfig = {
    gmail_user: '',
    gmail_app_password: '',
    telegram_bot_token: ''
};

// ============================================================================
// AIRTABLE API HELPER
// ============================================================================

async function airtableRequest(table, method = 'GET', body = null, recordId = null) {
    const url = recordId
        ? `${AIRTABLE_CONFIG.baseUrl}/${table}/${recordId}`
        : `${AIRTABLE_CONFIG.baseUrl}/${table}`;

    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${AIRTABLE_CONFIG.apiKey}`,
            'Content-Type': 'application/json'
        }
    };

    if (body) options.body = JSON.stringify(body);

    try {
        const response = await fetch(url, options);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || 'Request failed');
        return data;
    } catch (error) {
        console.error('Airtable Error:', error.message);
        throw error;
    }
}

// ============================================================================
// LOAD SYSTEM CONFIGURATION
// ============================================================================

async function loadSystemConfig() {
    try {
        console.log('Loading system configuration...');
        const response = await airtableRequest(AIRTABLE_CONFIG.tables.systemConfig);

        response.records.forEach(record => {
            const key = record.fields.config_key;
            const value = record.fields.config_value;
            if (systemConfig.hasOwnProperty(key)) {
                systemConfig[key] = value;
            }
        });

        console.log('System config loaded');
        console.log(`   Gmail: ${systemConfig.gmail_user || 'Not set'}`);
        console.log(`   Telegram: ${systemConfig.telegram_bot_token ? 'Configured' : 'Not set'}`);
    } catch (error) {
        console.error('Failed to load system config:', error.message);
    }
}

// ============================================================================
// VIRUSTOTAL SCANNING (Direct API - no CORS proxy needed)
// ============================================================================

async function scanUrl(url) {
    try {
        // Ensure URL has protocol
        const fullUrl = url.startsWith('http') ? url : `https://${url}`;
        const urlId = Buffer.from(fullUrl).toString('base64').replace(/=/g, '');

        console.log(`  Scanning: ${fullUrl}`);

        // Step 1: Check for cached results first
        let cachedData = null;
        let cachedDate = null;

        try {
            const cachedRes = await fetch(`${API_BASE}/urls/${urlId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });
            if (cachedRes.ok) {
                cachedData = await cachedRes.json();
                cachedDate = cachedData.data?.attributes?.last_analysis_date;
            }
        } catch (e) {
            // No cached results
        }

        const now = Date.now() / 1000;
        const ageHours = cachedDate ? (now - cachedDate) / 3600 : Infinity;

        // If results are < 24 hours old, use them
        if (cachedDate && ageHours < 24) {
            console.log(`     Using cached results (${ageHours.toFixed(1)} hours old)`);
            return buildResultFromVT(fullUrl, cachedData.data.attributes);
        }

        // Step 2: Request a rescan
        console.log(`     Requesting fresh scan...`);

        let analysisId = null;

        // Try rescan endpoint first (for known URLs)
        const rescanRes = await fetch(`${API_BASE}/urls/${urlId}/analyse`, {
            method: 'POST',
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });

        if (rescanRes.ok) {
            const rescanData = await rescanRes.json();
            analysisId = rescanData.data.id;
        } else if (rescanRes.status === 404) {
            // URL not in VT - submit it
            const submitRes = await fetch(`${API_BASE}/urls`, {
                method: 'POST',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `url=${encodeURIComponent(fullUrl)}`
            });
            if (submitRes.ok) {
                const submitData = await submitRes.json();
                analysisId = submitData.data.id;
            }
        }

        if (!analysisId) {
            throw new Error('Failed to submit scan');
        }

        console.log(`     Analysis ID: ${analysisId}`);

        // Step 3: Poll for results
        let analysisData;
        for (let i = 0; i < MAX_ATTEMPTS; i++) {
            await new Promise(r => setTimeout(r, POLL_INTERVAL));

            const res = await fetch(`${API_BASE}/analyses/${analysisId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });
            analysisData = await res.json();

            if (analysisData.data.attributes.status === "completed") {
                console.log(`     Scan completed!`);
                break;
            }
            console.log(`     Waiting (${i + 1}/${MAX_ATTEMPTS})...`);
        }

        if (analysisData.data.attributes.status !== "completed") {
            throw new Error("Scan did not complete in time");
        }

        return buildResultFromAnalysis(fullUrl, analysisData.data.attributes);

    } catch (error) {
        console.error(`     Scan failed: ${error.message}`);
        return {
            url,
            verdict: 'error',
            verdictExplanation: error.message,
            detections: 0,
            adRiskScore: 0,
            maliciousEngines: []
        };
    }
}

// Build result from /urls/{id} response
function buildResultFromVT(url, attrs) {
    const stats = attrs.last_analysis_stats;
    const allResults = attrs.last_analysis_results;
    return buildResult(url, stats, allResults, attrs.last_analysis_date);
}

// Build result from /analyses/{id} response
function buildResultFromAnalysis(url, attrs) {
    return buildResult(url, attrs.stats, attrs.results, attrs.date);
}

// Common result builder
function buildResult(url, stats, allResults, scanDate) {
    const detections = stats.malicious + stats.suspicious;
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

    let verdict = "clean";
    if (detections >= 5) verdict = "malicious";
    else if (detections > 0) verdict = "suspicious";

    const verdictExplanation =
        verdict === "clean"
            ? "No vendors flagged this URL."
            : verdict === "suspicious"
            ? "A few vendors flagged this as suspicious."
            : "Multiple vendors detected malware or phishing behavior.";

    const maliciousEngines = Object.entries(allResults)
        .filter(([_, r]) => r.category === "malicious")
        .map(([engine]) => engine);

    // Ad-impact scoring
    const weightMap = {
        "Google Safebrowsing": 10, "Fortinet": 9, "PhishTank": 8, "OpenPhish": 8,
        "BitDefender": 7, "ESET": 7, "Kaspersky": 7, "Sophos": 7,
        "McAfee": 6, "TrendMicro": 6, "Symantec": 6, "Avast": 6, "AVG": 6,
        "Comodo": 5, "Netcraft": 5, "Spamhaus": 5, "CRDF": 5, "CyRadar": 5
    };

    const flaggedByAdVendors = maliciousEngines.filter(engine =>
        Object.keys(weightMap).some(v => engine.toLowerCase().includes(v.toLowerCase()))
    );

    const adRiskScore = flaggedByAdVendors.reduce((sum, engine) => {
        const vendor = Object.keys(weightMap).find(v => engine.toLowerCase().includes(v.toLowerCase()));
        return sum + (weightMap[vendor] || 3);
    }, 0);

    let adImpactRisk = "safe";
    if (adRiskScore >= 16) adImpactRisk = "block-risk";
    else if (adRiskScore >= 9) adImpactRisk = "moderate";
    else if (adRiskScore > 0) adImpactRisk = "review";

    return {
        url,
        verdict,
        verdictExplanation,
        detections,
        totalEngines,
        maliciousEngines,
        flaggedByAdVendors,
        adRiskScore,
        adImpactRisk,
        hasAdImpact: adImpactRisk !== "safe",
        lastScanDate: new Date(scanDate * 1000).toISOString(),
        fullResponse: allResults
    };
}

// ============================================================================
// SCHEDULE CHECKING
// ============================================================================

function isScheduleDue(schedule) {
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase();
    const currentDate = now.getDate();

    const frequency = schedule.frequency;

    if (frequency === 'hourly') {
        return currentMinute === 0;
    }

    const scheduledTime = schedule.scheduledTime || '09:00';
    const [schedHour, schedMin] = scheduledTime.split(':').map(Number);
    const timeMatches = currentHour === schedHour && currentMinute === schedMin;

    if (frequency === 'daily') return timeMatches;

    if (frequency === 'weekly') {
        const scheduledDay = (schedule.scheduledDay || 'monday').toLowerCase();
        return timeMatches && currentDay === scheduledDay;
    }

    if (frequency === 'monthly') {
        const scheduledDate = schedule.scheduledDate || 1;
        return timeMatches && currentDate === scheduledDate;
    }

    return false;
}

// ============================================================================
// EMAIL ALERTS
// ============================================================================

async function sendEmailAlert(toEmail, url, engineNames, message) {
    if (!systemConfig.gmail_user || !systemConfig.gmail_app_password) {
        console.log('     Email not configured in SystemConfig');
        return false;
    }

    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: systemConfig.gmail_user,
                pass: systemConfig.gmail_app_password
            }
        });

        await transporter.sendMail({
            from: systemConfig.gmail_user,
            to: toEmail,
            subject: `Security Alert: ${url}`,
            html: `
                <h2>Security Alert Detected</h2>
                <p><strong>URL:</strong> ${url}</p>
                <p><strong>Flagged by:</strong> ${engineNames.join(', ')}</p>
                <p>${message}</p>
                <hr>
                <p style="color: #888; font-size: 12px;">URL Health Monitor</p>
            `
        });

        console.log(`     Email sent to: ${toEmail}`);
        return true;
    } catch (error) {
        console.error(`     Email failed: ${error.message}`);
        return false;
    }
}

// ============================================================================
// TELEGRAM ALERTS
// ============================================================================

async function sendTelegramAlert(chatId, message) {
    if (!systemConfig.telegram_bot_token) {
        console.log('     Telegram not configured in SystemConfig');
        return false;
    }

    try {
        const response = await fetch(
            `https://api.telegram.org/bot${systemConfig.telegram_bot_token}/sendMessage`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: message,
                    parse_mode: 'HTML'
                })
            }
        );

        if (response.ok) {
            console.log(`     Telegram sent to: ${chatId}`);
            return true;
        } else {
            const errorData = await response.json();
            console.error(`     Telegram failed: ${errorData.description}`);
            return false;
        }
    } catch (error) {
        console.error(`     Telegram error: ${error.message}`);
        return false;
    }
}

// ============================================================================
// DETECTION ALERT MANAGEMENT (Updated for new schema)
// ============================================================================

async function checkAndCreateAlert(urlId, userId, engineName, alertFrequencyHours) {
    try {
        const alertsResponse = await airtableRequest(AIRTABLE_CONFIG.tables.detectionAlerts);

        const existingAlert = alertsResponse.records.find(record => {
            const urlLinks = record.fields.url || [];
            const accountLinks = record.fields.account || []; // Changed from 'user'
            const alertEngine = record.fields.engine_name || '';

            return urlLinks.includes(urlId) &&
                   accountLinks.includes(userId) &&
                   alertEngine === engineName;
        });

        if (existingAlert) {
            if (existingAlert.fields.acknowledged) {
                console.log(`     ${engineName} - Already acknowledged, skipping`);
                return { shouldAlert: false };
            }

            // Check time since first detected (no last_alerted in new schema)
            const firstDetected = existingAlert.fields.first_detected;
            if (firstDetected && alertFrequencyHours > 0) {
                const hoursSince = (Date.now() - new Date(firstDetected).getTime()) / (1000 * 60 * 60);
                if (hoursSince < alertFrequencyHours) {
                    console.log(`     ${engineName} - Within ${alertFrequencyHours}h window, skipping`);
                    return { shouldAlert: false };
                }
            }

            return { shouldAlert: true, alertId: existingAlert.id, isNew: false };
        } else {
            // Create new alert (updated fields for new schema)
            console.log(`     ${engineName} - First detection, creating alert`);

            const newAlert = await airtableRequest(
                AIRTABLE_CONFIG.tables.detectionAlerts,
                'POST',
                {
                    fields: {
                        url: [urlId],
                        account: [userId], // Changed from 'user'
                        engine_name: engineName,
                        first_detected: new Date().toISOString(),
                        acknowledged: false
                    }
                }
            );

            return { shouldAlert: true, alertId: newAlert.id, isNew: true };
        }
    } catch (error) {
        console.error(`     Error checking alert for ${engineName}:`, error.message);
        return { shouldAlert: false };
    }
}

async function processDetectionAlerts(urlId, userId, maliciousEngines, alertFrequencyHours) {
    console.log(`  Processing detection alerts...`);

    const enginesThatShouldAlert = [];

    for (const engineName of maliciousEngines) {
        const result = await checkAndCreateAlert(urlId, userId, engineName, alertFrequencyHours);
        if (result.shouldAlert) {
            enginesThatShouldAlert.push(engineName);
        }
    }

    return enginesThatShouldAlert;
}

async function sendAlertsForDetection(url, user, maliciousEngines) {
    const emails = user.fields.alert_emails
        ? user.fields.alert_emails.split(/[\n,]/).map(e => e.trim()).filter(e => e)
        : [];
    const chatIds = user.fields.telegram_chat_ids
        ? user.fields.telegram_chat_ids.split(/[\n,]/).map(e => e.trim()).filter(e => e)
        : [];

    if (emails.length === 0 && chatIds.length === 0) {
        console.log('     No alert contacts configured for user');
        return;
    }

    const message = `Security Alert!\n\nURL: ${url}\nFlagged by: ${maliciousEngines.join(', ')}\n\nPlease review immediately.`;

    for (const email of emails) {
        await sendEmailAlert(email, url, maliciousEngines, message);
    }

    for (const chatId of chatIds) {
        await sendTelegramAlert(chatId, message);
    }
}

// ============================================================================
// PROCESS SCHEDULES (Updated for new schema)
// ============================================================================

async function processSchedules() {
    try {
        console.log('\nChecking schedules...');

        const schedulesResponse = await airtableRequest(AIRTABLE_CONFIG.tables.schedules);
        const enabledSchedules = schedulesResponse.records.filter(record =>
            record.fields.enabled !== false
        );

        console.log(`   Found ${enabledSchedules.length} enabled schedules`);

        for (const scheduleRecord of enabledSchedules) {
            // Parse rules JSON to get urlIds (new schema)
            let urlIds = [];
            try {
                const rules = JSON.parse(scheduleRecord.fields.rules || '{}');
                urlIds = rules.urlIds || [];
            } catch (e) {
                urlIds = [];
            }

            const schedule = {
                id: scheduleRecord.id,
                name: scheduleRecord.fields.name || 'Unnamed',
                frequency: scheduleRecord.fields.frequency,
                scheduledTime: scheduleRecord.fields.scheduled_time,
                scheduledDay: scheduleRecord.fields.scheduled_day,
                scheduledDate: scheduleRecord.fields.scheduled_date,
                urlIds: urlIds,
                accountLinks: scheduleRecord.fields.account || [] // Changed from 'user'
            };

            if (!isScheduleDue(schedule)) continue;

            console.log(`\nSchedule DUE: "${schedule.name}" (${schedule.frequency})`);

            if (schedule.accountLinks.length === 0) {
                console.log('   No user linked to schedule');
                continue;
            }

            const userId = schedule.accountLinks[0];
            const userResponse = await airtableRequest(AIRTABLE_CONFIG.tables.users, 'GET', null, userId);
            const alertFrequencyHours = userResponse.fields.alert_frequency_hours || DEFAULT_ALERT_INTERVAL_HOURS;

            if (urlIds.length === 0) {
                console.log('   No URLs in schedule');
                continue;
            }

            console.log(`   Scanning ${urlIds.length} URL(s)...`);

            for (const urlId of urlIds) {
                try {
                    const urlResponse = await airtableRequest(AIRTABLE_CONFIG.tables.urls, 'GET', null, urlId);
                    const urlToScan = urlResponse.fields.url;

                    const scanResult = await scanUrl(urlToScan);

                    // Save to ScanLogs (updated fields for new schema)
                    await airtableRequest(AIRTABLE_CONFIG.tables.scanLogs, 'POST', {
                        fields: {
                            url: [urlId],
                            scaneed_by: [userId], // New field (note typo in schema)
                            scan_timestamp: new Date().toISOString(),
                            status: scanResult.verdict,
                            detections: scanResult.detections || 0,
                            ad_risk_score: scanResult.adRiskScore || 0, // New field
                            result_json: JSON.stringify(scanResult)
                        }
                    });
                    console.log(`     Saved to ScanLogs`);

                    if (scanResult.maliciousEngines && scanResult.maliciousEngines.length > 0) {
                        const enginesThatNeedAlerting = await processDetectionAlerts(
                            urlId,
                            userId,
                            scanResult.maliciousEngines,
                            alertFrequencyHours
                        );

                        if (enginesThatNeedAlerting.length > 0) {
                            console.log(`  Sending alerts for ${enginesThatNeedAlerting.length} engine(s)...`);
                            await sendAlertsForDetection(urlToScan, userResponse, enginesThatNeedAlerting);
                        }
                    }

                } catch (error) {
                    console.error(`     Error scanning URL: ${error.message}`);
                }
            }

            // Update last_scan
            try {
                await airtableRequest(
                    AIRTABLE_CONFIG.tables.schedules,
                    'PATCH',
                    { fields: { last_scan: new Date().toISOString() } },
                    schedule.id
                );
            } catch (error) {
                console.error(`   Failed to update last_scan: ${error.message}`);
            }
        }

        console.log('Schedule check complete\n');

    } catch (error) {
        console.error('Error processing schedules:', error.message);
    }
}

// ============================================================================
// EXPRESS API SERVER
// ============================================================================

const app = express();
app.use(cors());
app.use(express.json());

// Manual scan endpoint - called from browser
app.post('/api/scan', async (req, res) => {
    try {
        const { url, urlId, userId } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        console.log(`\nAPI Scan request: ${url}`);

        const scanResult = await scanUrl(url);

        // Save to Airtable if IDs provided
        if (urlId && userId) {
            try {
                await airtableRequest(AIRTABLE_CONFIG.tables.scanLogs, 'POST', {
                    fields: {
                        url: [urlId],
                        scaneed_by: [userId],
                        scan_timestamp: new Date().toISOString(),
                        status: scanResult.verdict,
                        detections: scanResult.detections || 0,
                        ad_risk_score: scanResult.adRiskScore || 0,
                        result_json: JSON.stringify(scanResult)
                    }
                });
                console.log(`     Saved to Airtable`);
            } catch (e) {
                console.error(`     Failed to save to Airtable: ${e.message}`);
            }
        }

        res.json(scanResult);

    } catch (error) {
        console.error('Scan API error:', error);
        res.status(500).json({ error: 'Scan failed', message: error.message });
    }
});

// Batch scan endpoint
app.post('/api/scan-batch', async (req, res) => {
    try {
        const { urls, userId } = req.body;

        if (!urls || !Array.isArray(urls) || urls.length === 0) {
            return res.status(400).json({ error: 'URLs array required' });
        }

        console.log(`\nBatch scan request: ${urls.length} URLs`);

        const results = [];

        for (const item of urls) {
            const url = typeof item === 'string' ? item : item.url;
            const urlId = typeof item === 'object' ? item.urlId : null;

            const scanResult = await scanUrl(url);

            // Save to Airtable
            if (urlId && userId) {
                try {
                    await airtableRequest(AIRTABLE_CONFIG.tables.scanLogs, 'POST', {
                        fields: {
                            url: [urlId],
                            scaneed_by: [userId],
                            scan_timestamp: new Date().toISOString(),
                            status: scanResult.verdict,
                            detections: scanResult.detections || 0,
                            ad_risk_score: scanResult.adRiskScore || 0,
                            result_json: JSON.stringify(scanResult)
                        }
                    });
                } catch (e) {
                    console.error(`     Failed to save: ${e.message}`);
                }
            }

            results.push(scanResult);
        }

        res.json({ results });

    } catch (error) {
        console.error('Batch scan error:', error);
        res.status(500).json({ error: 'Batch scan failed', message: error.message });
    }
});

// Test Email
app.post('/api/test-email', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });

        const success = await sendEmailAlert(
            email,
            'https://example.com',
            ['Test'],
            'This is a test alert from URL Health Monitor.'
        );

        res.json({ success, message: success ? `Test email sent to ${email}` : 'Failed to send email' });
    } catch (error) {
        res.status(500).json({ error: 'Failed', message: error.message });
    }
});

// Test Telegram
app.post('/api/test-telegram', async (req, res) => {
    try {
        const { chatId } = req.body;
        if (!chatId) return res.status(400).json({ error: 'Chat ID required' });

        const success = await sendTelegramAlert(
            chatId,
            'Test Alert\n\nThis is a test from URL Health Monitor.'
        );

        res.json({ success, message: success ? `Test sent to ${chatId}` : 'Failed to send' });
    } catch (error) {
        res.status(500).json({ error: 'Failed', message: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'online', uptime: process.uptime() });
});

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    console.log('URL Health Monitor Scheduler Starting...\n');

    await loadSystemConfig();

    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
        console.log(`\nAPI server running on port ${PORT}`);
        console.log(`Endpoints:`);
        console.log(`  POST /api/scan         - Scan single URL`);
        console.log(`  POST /api/scan-batch   - Scan multiple URLs`);
        console.log(`  POST /api/test-email   - Test email alerts`);
        console.log(`  POST /api/test-telegram - Test Telegram alerts`);
        console.log(`  GET  /api/health       - Health check\n`);
    });

    console.log('Scheduler running every minute...');
    console.log('Press Ctrl+C to stop\n');

    cron.schedule('0 * * * * *', async () => {
        await processSchedules();
    });

    // Run once on startup
    console.log('Running initial schedule check...');
    await processSchedules();
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
