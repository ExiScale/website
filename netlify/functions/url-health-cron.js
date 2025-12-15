// URL Health Cron - Scheduled URL Scanning with Email Alerts
// Runs hourly to check enabled schedules and scan URLs that are due
// Sends email alerts via Klaviyo when malicious/suspicious URLs detected

const AIRTABLE_API_KEY = process.env.AIRTABLE_URL_HEALTH_API_KEY;
const AIRTABLE_BASE_ID = 'appZwri4LF6oF0QSB';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const KLAVIYO_API_KEY = process.env.EXISCALE_KLAVIYO_KEY;
const AIRTABLE_API = 'https://api.airtable.com/v0';

const TABLES = {
    schedules: 'Schedules',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    alerts: 'DetectionAlerts',
    users: 'Users'
};

// Helper: Make Airtable request
async function airtableRequest(table, method = 'GET', body = null, recordId = null) {
    let url = `${AIRTABLE_API}/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}`;
    if (recordId) url += `/${recordId}`;

    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
            'Content-Type': 'application/json'
        }
    };

    if (body && (method === 'POST' || method === 'PATCH')) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(`Airtable error: ${JSON.stringify(data.error)}`);
    }

    return data;
}

// Helper: Get all records with pagination
async function getAllRecords(table, filterFormula = null) {
    let allRecords = [];
    let offset = null;

    do {
        let url = `${AIRTABLE_API}/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?pageSize=100`;
        if (filterFormula) url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
        if (offset) url += `&offset=${offset}`;

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(`Airtable error: ${JSON.stringify(data.error)}`);

        allRecords = allRecords.concat(data.records);
        offset = data.offset;
    } while (offset);

    return allRecords;
}

// Send email alert via Klaviyo Track Event (triggers a flow)
async function sendKlaviyoAlert(email, urlScanned, status, detections, engines) {
    if (!KLAVIYO_API_KEY) {
        console.log('⚠️ KLAVIYO_API_KEY not configured, skipping email');
        return;
    }

    const statusLabel = status === 'malicious' ? 'MALICIOUS' : 'SUSPICIOUS';

    try {
        // Use Klaviyo Track API to create an event
        const response = await fetch('https://a.klaviyo.com/api/events/', {
            method: 'POST',
            headers: {
                'Authorization': `Klaviyo-API-Key ${KLAVIYO_API_KEY}`,
                'Content-Type': 'application/json',
                'revision': '2024-02-15'
            },
            body: JSON.stringify({
                data: {
                    type: 'event',
                    attributes: {
                        profile: {
                            data: {
                                type: 'profile',
                                attributes: {
                                    email: email
                                }
                            }
                        },
                        metric: {
                            data: {
                                type: 'metric',
                                attributes: {
                                    name: 'URL Health Alert'
                                }
                            }
                        },
                        properties: {
                            url: urlScanned,
                            status: status,
                            status_label: statusLabel,
                            detections: detections,
                            engines: engines.join(', '),
                            engine_list: engines,
                            dashboard_url: 'https://exiscale.com/tools/url-health/',
                            scan_time: new Date().toISOString()
                        },
                        time: new Date().toISOString()
                    }
                }
            })
        });

        if (response.ok) {
            console.log(`📧 Klaviyo event tracked for ${email}`);
            return true;
        } else {
            const result = await response.json();
            console.log(`❌ Klaviyo failed: ${JSON.stringify(result)}`);
            return false;
        }
    } catch (error) {
        console.log(`❌ Klaviyo error: ${error.message}`);
        return false;
    }
}

// Scan URL with VirusTotal
async function scanWithVirusTotal(urlToScan) {
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(urlToScan)}`
    });

    if (!submitResponse.ok) {
        throw new Error(`VirusTotal submit failed: ${submitResponse.status}`);
    }

    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;

    await new Promise(resolve => setTimeout(resolve, 3000));

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
    });

    if (!resultResponse.ok) {
        throw new Error(`VirusTotal result failed: ${resultResponse.status}`);
    }

    const resultData = await resultResponse.json();
    const stats = resultData.data.attributes.stats;
    const results = resultData.data.attributes.results || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const detections = malicious + suspicious;

    let status = 'clean';
    if (malicious > 0) status = 'malicious';
    else if (suspicious > 0) status = 'suspicious';

    // Get engine names that flagged it
    const flaggedEngines = Object.entries(results)
        .filter(([_, r]) => r.category === 'malicious' || r.category === 'suspicious')
        .map(([name, _]) => name);

    return {
        status,
        detections,
        stats,
        results,
        flaggedEngines,
        analysisId
    };
}

// Check if schedule is due
function isScheduleDue(schedule) {
    const now = new Date();
    const lastScan = schedule.fields.last_scan ? new Date(schedule.fields.last_scan) : null;
    const frequency = schedule.fields.frequency || 'daily';

    if (!lastScan) return true;

    const hoursSinceLastScan = (now - lastScan) / (1000 * 60 * 60);

    switch (frequency) {
        case 'hourly':
            return hoursSinceLastScan >= 1;
        case 'daily':
            return hoursSinceLastScan >= 24;
        case 'weekly':
            return hoursSinceLastScan >= 168;
        default:
            return hoursSinceLastScan >= 24;
    }
}

// Get URL IDs from schedule rules
function getUrlIds(schedule) {
    const rules = schedule.fields.rules;
    if (!rules) return [];

    try {
        if (typeof rules === 'string') {
            if (rules.startsWith('{')) {
                const parsed = JSON.parse(rules);
                return parsed.urlIds || [];
            }
            if (rules.startsWith('[')) {
                return JSON.parse(rules);
            }
        }
        return [];
    } catch (e) {
        console.log(`⚠️ Could not parse rules: ${rules}`);
        return [];
    }
}

exports.handler = async (event, context) => {
    console.log(`🕐 URL Health Cron Job Started: ${new Date().toISOString()}`);

    console.log(`📋 ENV Check - Base ID exists: ${!!AIRTABLE_BASE_ID}`);
    console.log(`📋 ENV Check - API Key exists: ${!!AIRTABLE_API_KEY}`);
    console.log(`📋 ENV Check - VT Key exists: ${!!VIRUSTOTAL_API_KEY}`);
    console.log(`📋 ENV Check - Klaviyo Key exists: ${!!KLAVIYO_API_KEY}`);

    if (!AIRTABLE_API_KEY || !VIRUSTOTAL_API_KEY) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Missing API keys' })
        };
    }

    const results = {
        checked: 0,
        due: 0,
        scanned: 0,
        alerts: 0,
        emailsSent: 0,
        errors: []
    };

    try {
        console.log(`📋 Fetching schedules from table: ${TABLES.schedules}`);
        const schedules = await getAllRecords(TABLES.schedules, '{enabled} = TRUE()');
        console.log(`📋 Found ${schedules.length} enabled schedules`);

        // Get all URLs for lookup
        const allUrls = await getAllRecords(TABLES.urls);
        const urlMap = {};
        allUrls.forEach(u => {
            urlMap[u.id] = u.fields.url;
        });

        // Get all users for email lookup
        const allUsers = await getAllRecords(TABLES.users);
        const userMap = {};
        allUsers.forEach(u => {
            userMap[u.id] = u.fields.username; // username contains email
        });

        for (const schedule of schedules) {
            results.checked++;
            const scheduleName = schedule.fields.name || 'Unnamed';

            try {
                if (!isScheduleDue(schedule)) {
                    console.log(`⏭️ Schedule "${scheduleName}" not due yet`);
                    continue;
                }

                results.due++;
                console.log(`✅ Schedule "${scheduleName}" is due - running scans`);

                const urlIds = getUrlIds(schedule);
                const accountId = schedule.fields.account ? schedule.fields.account[0] : null;
                const userEmail = accountId ? userMap[accountId] : null;

                for (const urlId of urlIds) {
                    const urlToScan = urlMap[urlId];
                    if (!urlToScan) {
                        console.log(`⚠️ URL ID ${urlId} not found`);
                        continue;
                    }

                    console.log(`🔍 Scanning: ${urlToScan}`);

                    try {
                        const scanResult = await scanWithVirusTotal(urlToScan);
                        results.scanned++;

                        // Save scan log
                        await airtableRequest(TABLES.scanLogs, 'POST', {
                            fields: {
                                url: [urlId],
                                scan_timestamp: new Date().toISOString(),
                                status: scanResult.status,
                                detections: scanResult.detections,
                                ad_risk_score: 0,
                                result_json: JSON.stringify(scanResult)
                            }
                        });

                        console.log(`✅ Saved scan log: ${scanResult.status}, ${scanResult.detections} detections`);

                        // If malicious or suspicious, create alerts and send email
                        if ((scanResult.status === 'malicious' || scanResult.status === 'suspicious') && accountId) {
                            results.alerts++;

                            // Create alerts in Airtable
                            for (const engineName of scanResult.flaggedEngines.slice(0, 5)) {
                                await airtableRequest(TABLES.alerts, 'POST', {
                                    fields: {
                                        url: [urlId],
                                        account: [accountId],
                                        engine_name: engineName,
                                        first_detected: new Date().toISOString(),
                                        acknowledged: false
                                    }
                                });
                                console.log(`🚨 Created alert for ${engineName}`);
                            }

                            // Send Klaviyo event for email notification
                            if (userEmail) {
                                const sent = await sendKlaviyoAlert(
                                    userEmail,
                                    urlToScan,
                                    scanResult.status,
                                    scanResult.detections,
                                    scanResult.flaggedEngines.slice(0, 5)
                                );
                                if (sent) results.emailsSent++;
                            }
                        }

                    } catch (scanError) {
                        console.log(`❌ Scan error for ${urlToScan}: ${scanError.message}`);
                    }
                }

                // Update last_scan timestamp
                await airtableRequest(TABLES.schedules, 'PATCH', {
                    fields: {
                        last_scan: new Date().toISOString()
                    }
                }, schedule.id);

                console.log(`✅ Schedule "${scheduleName}" completed`);

            } catch (scheduleError) {
                console.log(`❌ Error processing schedule "${scheduleName}": ${scheduleError}`);
                results.errors.push({ schedule: scheduleName, error: scheduleError.message });
            }
        }

    } catch (error) {
        console.log(`❌ Cron job error: ${error}`);
        results.errors.push({ error: error.message });
    }

    console.log(`🏁 Cron job completed: ${JSON.stringify(results, null, 2)}`);

    return {
        statusCode: 200,
        body: JSON.stringify(results)
    };
};
