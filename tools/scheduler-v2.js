/**
 * URLHealth Scheduler v2.0
 * Automated URL scanning based on configured schedules
 *
 * Run with: node scheduler-v2.js
 * Recommended: Use PM2 for production (pm2 start scheduler-v2.js --name urlhealth-scheduler)
 */

const https = require('https');
const http = require('http');

// Configuration
const AIRTABLE_API_KEY = 'patMUyJg0ED6dzx41.111935258c9b6eb1ec6af7d44487a2c83f13544b664ec225d3f6a590668aeab1';
const BASE_ID = 'appHPUKVa6Pnlj94y';
const PROXY = 'https://corsproxy.io/?';

// Table IDs
const TABLES = {
    Accounts: 'tblxhFFqMLfKE42eh',
    URLs: 'tblwAw5pyMnchorPj',
    Schedules: 'tblaQiR5ud8jR8Adh',
    ScanLogs: 'tblLkCmdsgivy5QFz',
    DetectionAlerts: 'tbltr2R6zauV3aLhh',
    SystemConfig: 'tblY10uLnCJliQrJS'
};

// System config cache
let systemConfig = {};

// Helper: Make Airtable API request
function airtableRequest(table, method = 'GET', body = null, recordId = null) {
    return new Promise((resolve, reject) => {
        const path = `/v0/${BASE_ID}/${table}${recordId ? `/${recordId}` : ''}`;

        const options = {
            hostname: 'api.airtable.com',
            path: path,
            method: method,
            headers: {
                'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    resolve(JSON.parse(data));
                } else {
                    reject(new Error(`Airtable API error: ${res.statusCode} - ${data}`));
                }
            });
        });

        req.on('error', reject);

        if (body) {
            req.write(JSON.stringify(body));
        }

        req.end();
    });
}

// Helper: Make HTTP/HTTPS request
function makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const isHttps = url.startsWith('https://');
        const lib = isHttps ? https : http;

        const req = lib.request(url, options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        resolve(data);
                    }
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                }
            });
        });

        req.on('error', reject);

        if (options.body) {
            req.write(options.body);
        }

        req.end();
    });
}

// Load system configuration
async function loadSystemConfig() {
    try {
        console.log('Loading system configuration...');
        const response = await airtableRequest(TABLES.SystemConfig);

        systemConfig = {};
        response.records.forEach(record => {
            systemConfig[record.fields.config_key] = record.fields.config_value;
        });

        console.log('System config loaded:', Object.keys(systemConfig).join(', '));
    } catch (error) {
        console.error('Failed to load system config:', error.message);
    }
}

// VirusTotal Scan
async function performVirusTotalScan(url) {
    const apiKey = systemConfig.virustotal_api_key;

    if (!apiKey || apiKey === 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
        throw new Error('VirusTotal API key not configured');
    }

    console.log(`  Scanning: ${url}`);

    // Submit URL
    const submitUrl = `${PROXY}https://www.virustotal.com/api/v3/urls`;
    const submitResponse = await makeRequest(submitUrl, {
        method: 'POST',
        headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
    });

    const analysisId = submitResponse.data.id;
    console.log(`  Analysis ID: ${analysisId}`);

    // Poll for results
    let attempts = 0;
    const maxAttempts = 10;

    while (attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 5000));

        const analysisUrl = `${PROXY}https://www.virustotal.com/api/v3/analyses/${analysisId}`;
        const analysisResponse = await makeRequest(analysisUrl, {
            headers: { 'x-apikey': apiKey }
        });

        if (analysisResponse.data.attributes.status === 'completed') {
            const stats = analysisResponse.data.attributes.stats;
            const results = analysisResponse.data.attributes.results;

            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const detections = malicious + suspicious;

            let status = 'clean';
            if (malicious >= 3) status = 'malicious';
            else if (malicious > 0 || suspicious > 0) status = 'suspicious';

            // Calculate ad-impact score
            const weightMap = {
                'Google Safebrowsing': 10,
                'Fortinet': 9,
                'PhishTank': 8,
                'OpenPhish': 8,
                'Netcraft': 7,
                'ESET': 7,
                'Sophos': 7,
                'Kaspersky': 7,
                'Bitdefender': 7,
                'CRDF': 6
            };

            let adRiskScore = 0;
            const flaggedByAdVendors = [];
            const maliciousEngines = [];
            const suspiciousEngines = [];

            Object.keys(results).forEach(engine => {
                const result = results[engine];
                if (result.category === 'malicious') {
                    maliciousEngines.push(engine);
                    if (weightMap[engine]) {
                        adRiskScore += weightMap[engine];
                        flaggedByAdVendors.push(engine);
                    }
                } else if (result.category === 'suspicious') {
                    suspiciousEngines.push(engine);
                }
            });

            console.log(`  Result: ${status} (${detections} detections, risk score: ${adRiskScore})`);

            return {
                status,
                detections,
                adRiskScore,
                fullResponse: analysisResponse,
                maliciousEngines,
                suspiciousEngines,
                flaggedByAdVendors
            };
        }

        attempts++;
    }

    throw new Error('Scan timeout');
}

// Send Email Alert
async function sendEmailAlert(account, url, scanResult) {
    const emailAddresses = account.fields.alert_emails;
    if (!emailAddresses || !emailAddresses.trim()) {
        console.log('  No email addresses configured');
        return;
    }

    const gmailUser = systemConfig.gmail_user;
    const gmailPassword = systemConfig.gmail_app_password;

    if (!gmailUser || !gmailPassword || gmailUser.includes('YOUR_')) {
        console.log('  Gmail not configured, skipping email');
        return;
    }

    const emails = emailAddresses.split(/[\n,]/).map(e => e.trim()).filter(e => e);

    console.log(`  Sending email alerts to: ${emails.join(', ')}`);

    // In production, use nodemailer here
    console.log('  Email alert would be sent (nodemailer integration needed)');
}

// Send Telegram Alert
async function sendTelegramAlert(account, url, scanResult) {
    const chatIds = account.fields.telegram_chat_ids;
    if (!chatIds || !chatIds.trim()) {
        console.log('  No Telegram chat IDs configured');
        return;
    }

    const botToken = systemConfig.telegram_bot_token;

    if (!botToken || botToken.includes('YOUR_')) {
        console.log('  Telegram not configured, skipping');
        return;
    }

    const ids = chatIds.split(/[\n,]/).map(id => id.trim()).filter(id => id);

    console.log(`  Sending Telegram alerts to: ${ids.join(', ')}`);

    const message = `🚨 URLHealth Alert\n\n${url} flagged!\n\nStatus: ${scanResult.status}\nDetections: ${scanResult.detections}\nRisk Score: ${scanResult.adRiskScore}`;

    for (const chatId of ids) {
        try {
            const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
            await makeRequest(telegramUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: message
                })
            });
            console.log(`  Sent to Telegram chat ${chatId}`);
        } catch (error) {
            console.error(`  Failed to send to ${chatId}:`, error.message);
        }
    }
}

// Process Detection Alerts
async function processDetectionAlerts(urlId, account, scanResult) {
    if (scanResult.detections === 0) return;

    console.log('  Processing detection alerts...');

    const urlResponse = await airtableRequest(TABLES.URLs, 'GET', null, urlId);
    const url = urlResponse.fields.url;

    // Send alerts
    await sendEmailAlert(account, url, scanResult);
    await sendTelegramAlert(account, url, scanResult);

    // Create alert records for each malicious engine
    for (const engine of scanResult.maliciousEngines) {
        try {
            // Check if alert already exists for this URL + engine
            const existingAlertsResponse = await airtableRequest(TABLES.DetectionAlerts);
            const existingAlert = existingAlertsResponse.records.find(alert =>
                alert.fields.url && alert.fields.url.includes(urlId) &&
                alert.fields.engine_name === engine &&
                !alert.fields.acknowledged
            );

            if (existingAlert) {
                // Update existing alert
                const currentCount = existingAlert.fields.alert_count || 1;
                await airtableRequest(TABLES.DetectionAlerts, 'PATCH', {
                    fields: {
                        last_alerted: new Date().toISOString(),
                        alert_count: currentCount + 1
                    }
                }, existingAlert.id);
                console.log(`  Updated existing alert for ${engine}`);
            } else {
                // Create new alert with last_alerted set (since we just sent it above)
                await airtableRequest(TABLES.DetectionAlerts, 'POST', {
                    fields: {
                        url: [urlId],
                        account: [account.id],
                        engine_name: engine,
                        first_detected: new Date().toISOString(),
                        last_alerted: new Date().toISOString(),
                        acknowledged: false,
                        alert_count: 1
                    }
                });
                console.log(`  Created new alert for ${engine}`);
            }
        } catch (error) {
            console.error(`  Failed to create alert for ${engine}:`, error.message);
        }
    }
}

// Generate acknowledgement token
function generateAckToken() {
    return Math.random().toString(36).substr(2) + Date.now().toString(36);
}

// Scan URLs for a schedule
async function scanScheduleUrls(schedule, account) {
    console.log(`\nProcessing schedule: ${schedule.fields.name}`);

    const rules = schedule.fields.rules ? JSON.parse(schedule.fields.rules) : {};
    const urlIds = rules.urlIds || [];

    if (urlIds.length === 0) {
        console.log('  No URLs to scan');
        return;
    }

    console.log(`  Scanning ${urlIds.length} URL(s)...`);

    for (const urlId of urlIds) {
        try {
            // Get URL details
            const urlResponse = await airtableRequest(TABLES.URLs, 'GET', null, urlId);
            const url = urlResponse.fields.url;

            // Perform scan
            const scanResult = await performVirusTotalScan(url);

            // Save scan log
            await airtableRequest(TABLES.ScanLogs, 'POST', {
                fields: {
                    scan_id: `scan_${Date.now()}`,
                    url: [urlId],
                    scan_timestamp: new Date().toISOString(),
                    status: scanResult.status,
                    detections: scanResult.detections,
                    ad_risk_score: scanResult.adRiskScore,
                    result_json: JSON.stringify(scanResult.fullResponse),
                    acknowledged: false
                }
            });

            // Process alerts
            await processDetectionAlerts(urlId, account, scanResult);

        } catch (error) {
            console.error(`  Error scanning URL ${urlId}:`, error.message);
        }
    }

    // Update last_scan time
    await airtableRequest(TABLES.Schedules, 'PATCH', {
        fields: { last_scan: new Date().toISOString() }
    }, schedule.id);

    console.log('  Schedule complete!');
}

// Check if schedule should run now
function shouldRunSchedule(schedule) {
    const now = new Date();
    const frequency = schedule.fields.frequency;

    // Check if schedule is enabled
    if (!schedule.fields.enabled) {
        return false;
    }

    // Check last scan time (don't run if already ran in last minute)
    if (schedule.fields.last_scan) {
        const lastScan = new Date(schedule.fields.last_scan);
        const minutesSinceLastScan = (now - lastScan) / 1000 / 60;
        if (minutesSinceLastScan < 1) {
            return false;
        }
    }

    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'lowercase' });
    const currentDate = now.getDate();

    switch (frequency) {
        case 'hourly':
            // Run at the top of each hour (XX:00)
            return currentMinute === 0;

        case 'daily':
            const scheduledTime = schedule.fields.scheduled_time || '09:00';
            const [schedHour, schedMin] = scheduledTime.split(':').map(Number);
            return currentHour === schedHour && currentMinute === schedMin;

        case 'weekly':
            const scheduledDay = schedule.fields.scheduled_day || 'monday';
            const weeklyTime = schedule.fields.scheduled_time || '09:00';
            const [weekHour, weekMin] = weeklyTime.split(':').map(Number);
            return currentDay === scheduledDay.toLowerCase() &&
                   currentHour === weekHour &&
                   currentMinute === weekMin;

        case 'monthly':
            const scheduledDate = schedule.fields.scheduled_date || 1;
            const monthlyTime = schedule.fields.scheduled_time || '09:00';
            const [monthHour, monthMin] = monthlyTime.split(':').map(Number);
            return currentDate === scheduledDate &&
                   currentHour === monthHour &&
                   currentMinute === monthMin;

        default:
            return false;
    }
}

// Check and Send Pending Alerts
async function checkAndSendAlerts() {
    try {
        console.log('\n--- Checking for pending alerts ---');

        // Get all unacknowledged alerts
        const alertsResponse = await airtableRequest(TABLES.DetectionAlerts);
        const unacknowledgedAlerts = alertsResponse.records.filter(alert => !alert.fields.acknowledged);

        if (unacknowledgedAlerts.length === 0) {
            console.log('No pending alerts');
            return;
        }

        console.log(`Found ${unacknowledgedAlerts.length} unacknowledged alert(s)`);

        const now = Date.now();
        const SIX_HOURS = 6 * 60 * 60 * 1000; // 6 hours in milliseconds

        for (const alert of unacknowledgedAlerts) {
            try {
                const lastAlerted = alert.fields.last_alerted ? new Date(alert.fields.last_alerted).getTime() : 0;
                const hoursSinceLastAlert = (now - lastAlerted) / (60 * 60 * 1000);

                // Send if never alerted OR if 6+ hours have passed
                if (!alert.fields.last_alerted || (now - lastAlerted) >= SIX_HOURS) {
                    console.log(`  Alert ${alert.id}: ${hoursSinceLastAlert.toFixed(1)}h since last alert - SENDING`);

                    // Get URL and account info
                    const urlId = alert.fields.url[0];
                    const accountId = alert.fields.account[0];

                    const urlResponse = await airtableRequest(TABLES.URLs, 'GET', null, urlId);
                    const url = urlResponse.fields.url;
                    const account = await airtableRequest(TABLES.Accounts, 'GET', null, accountId);

                    // Create scan result object for alert formatting
                    const scanResult = {
                        status: 'malicious',
                        detections: 1,
                        adRiskScore: 0,
                        maliciousEngines: [alert.fields.engine_name]
                    };

                    // Send alerts
                    await sendEmailAlert(account, url, scanResult);
                    await sendTelegramAlert(account, url, scanResult);

                    // Update alert record
                    const currentCount = alert.fields.alert_count || 0;
                    await airtableRequest(TABLES.DetectionAlerts, 'PATCH', {
                        fields: {
                            last_alerted: new Date().toISOString(),
                            alert_count: currentCount + 1
                        }
                    }, alert.id);

                    console.log(`  ✓ Alert sent and updated`);
                } else {
                    console.log(`  Alert ${alert.id}: ${hoursSinceLastAlert.toFixed(1)}h since last alert - skipping (< 6h)`);
                }
            } catch (error) {
                console.error(`  Error processing alert ${alert.id}:`, error.message);
            }
        }

    } catch (error) {
        console.error('Alert checking error:', error.message);
    }
}

// Main scheduler loop
async function checkSchedules() {
    try {
        console.log('\n=== Checking schedules ===', new Date().toLocaleString());

        // Load schedules
        const schedulesResponse = await airtableRequest(TABLES.Schedules);
        const schedules = schedulesResponse.records;

        console.log(`Found ${schedules.length} total schedule(s)`);

        for (const schedule of schedules) {
            if (shouldRunSchedule(schedule)) {
                try {
                    // Get account info
                    const accountId = schedule.fields.account[0];
                    const account = await airtableRequest(TABLES.Accounts, 'GET', null, accountId);

                    await scanScheduleUrls(schedule, account);
                } catch (error) {
                    console.error(`Error processing schedule ${schedule.id}:`, error.message);
                }
            }
        }

        // Check and send pending alerts
        await checkAndSendAlerts();

    } catch (error) {
        console.error('Scheduler error:', error.message);
    }
}

// Initialize and run
async function main() {
    console.log('===================================');
    console.log('URLHealth Scheduler v2.0 Starting');
    console.log('===================================');

    // Load system config once at startup
    await loadSystemConfig();

    // Initial check
    await checkSchedules();

    // Run every minute
    setInterval(checkSchedules, 60 * 1000);

    console.log('\nScheduler is running. Press Ctrl+C to stop.\n');
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\nShutting down scheduler...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\nShutting down scheduler...');
    process.exit(0);
});

// Start the scheduler
main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
