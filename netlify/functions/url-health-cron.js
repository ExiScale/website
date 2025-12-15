// URL Health Cron - Scheduled URL Scanning
// Runs hourly to check enabled schedules and scan URLs that are due

const AIRTABLE_API_KEY = process.env.AIRTABLE_URL_HEALTH_API_KEY;
const AIRTABLE_BASE_ID = 'appZwri4LF6oF0QSB';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const AIRTABLE_API = 'https://api.airtable.com/v0';

const TABLES = {
    schedules: 'Schedules',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    alerts: 'DetectionAlerts'
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

// Scan URL with VirusTotal
async function scanWithVirusTotal(urlToScan) {
    // Submit URL for scanning
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

    // Wait a bit for analysis
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Get analysis results
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

    return {
        status,
        detections,
        stats,
        results,
        analysisId
    };
}

// Check if schedule is due
function isScheduleDue(schedule) {
    const now = new Date();
    const lastScan = schedule.fields.last_scan ? new Date(schedule.fields.last_scan) : null;
    const frequency = schedule.fields.frequency || 'daily';

    if (!lastScan) return true; // Never scanned

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

    // Check env vars
    console.log(`📋 ENV Check - Base ID exists: ${!!AIRTABLE_BASE_ID}`);
    console.log(`📋 ENV Check - API Key exists: ${!!AIRTABLE_API_KEY}`);
    console.log(`📋 ENV Check - VT Key exists: ${!!VIRUSTOTAL_API_KEY}`);

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
        errors: []
    };

    try {
        // Get all enabled schedules
        console.log(`📋 Fetching schedules from table: ${TABLES.schedules}`);
        const schedules = await getAllRecords(TABLES.schedules, '{enabled} = TRUE()');
        console.log(`📋 Found ${schedules.length} enabled schedules`);

        // Get all URLs for lookup
        const allUrls = await getAllRecords(TABLES.urls);
        const urlMap = {};
        allUrls.forEach(u => {
            urlMap[u.id] = u.fields.url;
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

                        // Save scan log using FIELD NAMES
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

                        // Create alerts for malicious detections
                        if (scanResult.status === 'malicious' && accountId) {
                            const maliciousEngines = Object.entries(scanResult.results || {})
                                .filter(([_, r]) => r.category === 'malicious')
                                .map(([name, _]) => name);

                            for (const engineName of maliciousEngines.slice(0, 5)) {
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
                        }

                    } catch (scanError) {
                        console.log(`❌ Scan error for ${urlToScan}: ${scanError.message}`);
                    }
                }

                // Update last_scan timestamp using FIELD NAMES
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
