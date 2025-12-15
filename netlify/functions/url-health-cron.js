// URL Health Scheduled Scanner
// Runs on a schedule to execute due scans

const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

const TABLES = {
    schedules: 'Schedules',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    alerts: 'Alerts'
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

// Get all records with optional filter
async function getAllRecords(table, filterFormula = null) {
    let allRecords = [];
    let offset = null;
    
    do {
        let url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?pageSize=100`;
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
    const lastScan = schedule.fields.last_scan ? new Date(schedule.fields.last_scan) : null;
    const frequency = schedule.fields.frequency;
    
    // If never scanned, it's due
    if (!lastScan) return true;
    
    const hoursSinceLastScan = (now - lastScan) / (1000 * 60 * 60);
    const daysSinceLastScan = hoursSinceLastScan / 24;
    
    switch (frequency) {
        case 'hourly':
            return hoursSinceLastScan >= 1;
        case 'daily':
            // Check if scheduled_time matches (if set)
            if (schedule.fields.scheduled_time) {
                const [hour, minute] = schedule.fields.scheduled_time.split(':').map(Number);
                const nowHour = now.getUTCHours();
                const nowMinute = now.getUTCMinutes();
                // Run if it's the right hour and hasn't run today
                if (nowHour === hour && daysSinceLastScan >= 1) {
                    return true;
                }
                return false;
            }
            return daysSinceLastScan >= 1;
        case 'weekly':
            // Check if scheduled_day matches (if set)
            if (schedule.fields.scheduled_day) {
                const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
                const scheduledDayIndex = days.indexOf(schedule.fields.scheduled_day.toLowerCase());
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
    const rules = schedule.fields.rules;
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
    
    const results = {
        checked: 0,
        due: 0,
        scanned: 0,
        errors: []
    };

    try {
        // Get all enabled schedules
        const schedules = await getAllRecords(TABLES.schedules, '{enabled} = TRUE()');
        results.checked = schedules.length;
        console.log(`📋 Found ${schedules.length} enabled schedules`);

        // Get all URLs for reference
        const allUrls = await getAllRecords(TABLES.urls);
        const urlMap = {};
        allUrls.forEach(u => {
            urlMap[u.id] = u.fields.url;
        });

        // Process each schedule
        for (const schedule of schedules) {
            try {
                if (!isScheduleDue(schedule)) {
                    console.log(`⏭️ Schedule "${schedule.fields.name}" not due yet`);
                    continue;
                }

                results.due++;
                console.log(`✅ Schedule "${schedule.fields.name}" is due - running scans`);

                // Get URL IDs from the schedule
                const urlIds = getUrlIdsFromSchedule(schedule);
                
                if (urlIds.length === 0) {
                    console.log(`⚠️ No URLs configured for schedule "${schedule.fields.name}"`);
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
                    
                    // Save scan log
                    const accountId = schedule.fields.account?.[0] || null;
                    await airtableRequest(TABLES.scanLogs, 'POST', {
                        fields: {
                            url: [urlId],
                            scan_timestamp: new Date().toISOString(),
                            status: scanResult.verdict,
                            detections: scanResult.detections || 0,
                            ad_risk_score: 0,
                            result_json: JSON.stringify(scanResult),
                            ...(accountId && { scanned_by: [accountId] })
                        }
                    });

                    results.scanned++;

                    // Create alert if malicious
                    if (scanResult.verdict === 'malicious' && accountId) {
                        await airtableRequest(TABLES.alerts, 'POST', {
                            fields: {
                                url: [urlId],
                                account: [accountId],
                                alert_type: 'malicious_detection',
                                message: `Scheduled scan detected malicious content: ${scanResult.detections} vendors flagged this URL`,
                                created_at: new Date().toISOString(),
                                status: 'unread'
                            }
                        });
                        console.log(`🚨 Alert created for malicious URL: ${urlText}`);
                    }

                    // Small delay between scans to avoid rate limiting
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }

                // Update last_scan timestamp
                await airtableRequest(TABLES.schedules, 'PATCH', {
                    fields: {
                        last_scan: new Date().toISOString()
                    }
                }, schedule.id);

                console.log(`✅ Schedule "${schedule.fields.name}" completed`);

            } catch (scheduleError) {
                console.error(`❌ Error processing schedule "${schedule.fields.name}":`, scheduleError);
                results.errors.push({
                    schedule: schedule.fields.name,
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
