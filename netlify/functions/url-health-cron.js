// URL Health Scheduled Scanner
// Runs on a schedule to execute due scans

const AIRTABLE_API_KEY = process.env.AIRTABLE_URL_HEALTH_API_KEY;
const AIRTABLE_BASE_ID = 'appZwri4LF6oF0QSB';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Table names (must match exactly what's in Airtable)
const TABLES = {
    schedules: 'Schedules',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    alerts: 'DetectionAlerts'
};

// Field IDs for Schedules table
const SCHEDULE_FIELDS = {
    name: 'fldGabCZ7h5gjDuSS',
    account: 'fldjkFwADD1Ij4EVs',
    frequency: 'fldHQxA8HH6YVhvay',
    enabled: 'fldt6FgE1yHFwOayj',
    scheduled_time: 'fldFsGMSx1058GBah',
    scheduled_day: 'fldhBYiRMKKQFR8yb',
    rules: 'fldtpHgjNy11ghWv4',
    last_scan: 'fld1DFgZ4vpcM2MSb'
};

// Field IDs for URLs table
const URL_FIELDS = {
    url: 'fld08YBIrSWdPbsD1'
};

// Field IDs for ScanLogs table
const SCANLOG_FIELDS = {
    url: 'fld0vDbZi6z8NkQr5',
    scan_timestamp: 'fld7DBPtFFT9qn4Qd',
    status: 'fldt0JXOqd1uqF5Ng',
    detections: 'fldzJsEVIHQawX1uV',
    ad_risk_score: 'fldIFl1XLkGp73WQq',
    result_json: 'fldG8e0y7Kp19ZlTI',
    scanned_by: 'fldPmZQYjdF8kGKN6'
};

// Field IDs for DetectionAlerts table
const ALERT_FIELDS = {
    url: 'fldwGPOAUsWIwCNMn',
    account: 'fldszN7Y8jhlvWh5e',
    engine_name: 'fldjp5WpmyWUPJmmB',
    first_detected: 'fldQDrUQimH6qwS7P',
    acknowledged: 'fldQY7jwX0SclE34y'
};

// Airtable API helper
async function airtableRequest(table, method = 'GET', body = null, recordId = null) {
    const url = recordId 
        ? `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}/${recordId}`
        : `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}`;
    
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
    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Airtable error: ${error}`);
    }
    
    if (method === 'DELETE') return { success: true };
    return response.json();
}

// Get all records with optional filter - returns field IDs
async function getAllRecords(table, filterFormula = null) {
    let allRecords = [];
    let offset = null;
    
    do {
        let url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?pageSize=100&returnFieldsByFieldId=true`;
        if (filterFormula) url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
        if (offset) url += `&offset=${offset}`;
        
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
        });
        
        if (!response.ok) throw new Error(`Airtable error: ${await response.text()}`);
        
        const data = await response.json();
        allRecords = allRecords.concat(data.records || []);
        offset = data.offset;
    } while (offset);
    
    return allRecords;
}

// Scan a URL using VirusTotal
async function scanUrl(url) {
    try {
        // Submit URL for scanning
        const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        if (!submitResponse.ok) {
            throw new Error(`VirusTotal submit failed: ${submitResponse.status}`);
        }

        const submitData = await submitResponse.json();
        const analysisId = submitData.data.id;

        // Wait for analysis to complete
        await new Promise(resolve => setTimeout(resolve, 15000));

        // Get analysis results
        const analysisResponse = await fetch(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } }
        );

        if (!analysisResponse.ok) {
            throw new Error(`VirusTotal analysis failed: ${analysisResponse.status}`);
        }

        const analysisData = await analysisResponse.json();
        const stats = analysisData.data.attributes.stats;
        const detections = stats.malicious + stats.suspicious;
        const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

        let verdict = 'clean';
        if (stats.malicious > 0) verdict = 'malicious';
        else if (stats.suspicious > 0) verdict = 'suspicious';

        return {
            success: true,
            verdict,
            detections,
            totalEngines,
            stats
        };
    } catch (error) {
        console.error(`Error scanning ${url}:`, error.message);
        return {
            success: false,
            verdict: 'error',
            detections: 0,
            error: error.message
        };
    }
}

// Check if a schedule is due to run
function isScheduleDue(schedule) {
    const now = new Date();
    const lastScan = schedule.fields[SCHEDULE_FIELDS.last_scan] ? new Date(schedule.fields[SCHEDULE_FIELDS.last_scan]) : null;
    const frequency = schedule.fields[SCHEDULE_FIELDS.frequency];
    
    // If never scanned, it's due
    if (!lastScan) return true;
    
    const hoursSinceLastScan = (now - lastScan) / (1000 * 60 * 60);
    const daysSinceLastScan = hoursSinceLastScan / 24;
    
    switch (frequency) {
        case 'hourly':
            return hoursSinceLastScan >= 1;
        case 'daily':
            // Check if scheduled_time matches (if set)
            if (schedule.fields[SCHEDULE_FIELDS.scheduled_time]) {
                const [hour, minute] = schedule.fields[SCHEDULE_FIELDS.scheduled_time].split(':').map(Number);
                const nowHour = now.getUTCHours();
                // Run if it's the right hour and hasn't run today
                if (nowHour === hour && daysSinceLastScan >= 1) {
                    return true;
                }
                return false;
            }
            return daysSinceLastScan >= 1;
        case 'weekly':
            // Check if scheduled_day matches (if set)
            if (schedule.fields[SCHEDULE_FIELDS.scheduled_day]) {
                const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
                const scheduledDayIndex = days.indexOf(schedule.fields[SCHEDULE_FIELDS.scheduled_day].toLowerCase());
                const todayIndex = now.getUTCDay();
                if (scheduledDayIndex === todayIndex && daysSinceLastScan >= 7) {
                    return true;
                }
                return false;
            }
            return daysSinceLastScan >= 7;
        default:
            return false;
    }
}

// Parse URL IDs from rules field
function getUrlIdsFromSchedule(schedule) {
    const rules = schedule.fields[SCHEDULE_FIELDS.rules];
    if (!rules) return [];
    
    try {
        // Handle JSON format: {"urlIds":["rec123","rec456"]}
        if (rules.startsWith('{')) {
            const parsed = JSON.parse(rules);
            return parsed.urlIds || [];
        }
        // Handle array format: ["rec123","rec456"]
        if (rules.startsWith('[')) {
            return JSON.parse(rules);
        }
    } catch (e) {
        console.error('Error parsing rules:', e);
    }
    return [];
}

// Main handler
exports.handler = async (event, context) => {
    console.log('🕐 URL Health Cron Job Started:', new Date().toISOString());
    
    // Debug: Check environment variables
    console.log('📋 ENV Check - Base ID exists:', !!AIRTABLE_BASE_ID);
    console.log('📋 ENV Check - API Key exists:', !!AIRTABLE_API_KEY);
    console.log('📋 ENV Check - VT Key exists:', !!VIRUSTOTAL_API_KEY);
    
    const results = {
        checked: 0,
        due: 0,
        scanned: 0,
        errors: []
    };

    try {
        // Get all enabled schedules (filter uses field NAME)
        console.log('📋 Fetching schedules from table:', TABLES.schedules);
        const schedules = await getAllRecords(TABLES.schedules, '{enabled} = TRUE()');
        results.checked = schedules.length;
        console.log(`📋 Found ${schedules.length} enabled schedules`);

        // Get all URLs for reference
        const allUrls = await getAllRecords(TABLES.urls);
        const urlMap = {};
        allUrls.forEach(u => {
            urlMap[u.id] = u.fields[URL_FIELDS.url];
        });

        // Process each schedule
        for (const schedule of schedules) {
            try {
                const scheduleName = schedule.fields[SCHEDULE_FIELDS.name] || 'Unnamed';
                
                if (!isScheduleDue(schedule)) {
                    console.log(`⏭️ Schedule "${scheduleName}" not due yet`);
                    continue;
                }

                results.due++;
                console.log(`✅ Schedule "${scheduleName}" is due - running scans`);

                // Get URL IDs from the schedule
                const urlIds = getUrlIdsFromSchedule(schedule);
                
                if (urlIds.length === 0) {
                    console.log(`⚠️ No URLs configured for schedule "${scheduleName}"`);
                    continue;
                }

                // Scan each URL
                for (const urlId of urlIds) {
                    const urlText = urlMap[urlId];
                    if (!urlText) {
                        console.log(`⚠️ URL ID ${urlId} not found`);
                        continue;
                    }

                    console.log(`🔍 Scanning: ${urlText}`);
                    const scanResult = await scanUrl(urlText);
                    
                    // Save scan log using field IDs
                    const accountIds = schedule.fields[SCHEDULE_FIELDS.account];
                    const accountId = Array.isArray(accountIds) ? accountIds[0] : null;
                    
                    await airtableRequest(TABLES.scanLogs, 'POST', {
                        fields: {
                            [SCANLOG_FIELDS.url]: [urlId],
                            [SCANLOG_FIELDS.scan_timestamp]: new Date().toISOString(),
                            [SCANLOG_FIELDS.status]: scanResult.verdict,
                            [SCANLOG_FIELDS.detections]: scanResult.detections || 0,
                            [SCANLOG_FIELDS.ad_risk_score]: 0,
                            [SCANLOG_FIELDS.result_json]: JSON.stringify(scanResult),
                            ...(accountId && { [SCANLOG_FIELDS.scanned_by]: [accountId] })
                        }
                    });

                    results.scanned++;

                    // Create alert if malicious
                    if (scanResult.verdict === 'malicious' && accountId) {
                        await airtableRequest(TABLES.alerts, 'POST', {
                            fields: {
                                [ALERT_FIELDS.url]: [urlId],
                                [ALERT_FIELDS.account]: [accountId],
                                [ALERT_FIELDS.engine_name]: 'Scheduled Scan',
                                [ALERT_FIELDS.first_detected]: new Date().toISOString(),
                                [ALERT_FIELDS.acknowledged]: false
                            }
                        });
                        console.log(`🚨 Alert created for malicious URL: ${urlText}`);
                    }

                    // Small delay between scans to avoid rate limiting
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }

                // Update last_scan timestamp using field ID
                await airtableRequest(TABLES.schedules, 'PATCH', {
                    fields: {
                        [SCHEDULE_FIELDS.last_scan]: new Date().toISOString()
                    }
                }, schedule.id);

                console.log(`✅ Schedule "${scheduleName}" completed`);

            } catch (scheduleError) {
                const scheduleName = schedule.fields[SCHEDULE_FIELDS.name] || 'Unknown';
                console.error(`❌ Error processing schedule "${scheduleName}":`, scheduleError);
                results.errors.push({
                    schedule: scheduleName,
                    error: scheduleError.message
                });
            }
        }

        console.log('🏁 Cron job completed:', results);
        
        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Scheduled scans completed',
                results
            })
        };

    } catch (error) {
        console.error('❌ Cron job failed:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({
                error: error.message,
                results
            })
        };
    }
};
