// URL Health - Airtable Operations Function v5.2 DEBUG
// Uses Field IDs for READING, Field Names for WRITING

const AIRTABLE_API_KEY = process.env.AIRTABLE_URL_HEALTH_API_KEY;
const AIRTABLE_BASE_ID = 'appZwri4LF6oF0QSB';
const AIRTABLE_API = 'https://api.airtable.com/v0';

// Table names
const TABLES = {
    users: 'Users',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    schedules: 'Schedules',
    alerts: 'DetectionAlerts'
};

// Field IDs - immune to field name changes
const FIELDS = {
    // Users table
    users: {
        username: 'fldTCQ88S6vZjo4AY',
        email: 'fldH5zPtaEtItPeGu',
        urls: 'fldx0i1b6bC8Z8ndz',
        schedules: 'fldfskRWTImgPLQjk',
        scanLogs: 'fldiJtgEpBmIbyfrx',
        detectionAlerts: 'fld6cH4hIPyZSbSY7'
    },
    // URLs table
    urls: {
        url: 'fld08YBIrSWdPbsD1',
        tags: 'fldF7Hh1w0dWnt9n4',
        added_by: 'fldTyt1Z3FM5UbQgE',
        added_at: 'fld7EJsunaY0yT4FZ',
        scanLogs: 'fldjTbsaETsFCKxk3',
        detectionAlerts: 'fld3Vw1grIf6mk1ZJ'
    },
    // ScanLogs table
    scanLogs: {
        scan_id: 'fldEiYwuZFTjvmSho',
        url: 'fld0vDbZi6z8NkQr5',
        scan_timestamp: 'fld7DBPtFFT9qn4Qd',
        status: 'fldt0JXOqd1uqF5Ng',
        detections: 'fldzJsEVIHQawX1uV',
        ad_risk_score: 'fldIFl1XLkGp73WQq',
        result_json: 'fldG8e0y7Kp19ZlTI',
        scanned_by: 'fldPmZQYjdF8kGKN6',
        acknowledged: 'fldJmpMn3zfIX4vfz'
    },
    // Schedules table
    schedules: {
        name: 'fldGabCZ7h5gjDuSS',
        account: 'fldjkFwADD1Ij4EVs',
        frequency: 'fldHQxA8HH6YVhvay',
        enabled: 'fldt6FgE1yHFwOayj',
        scheduled_time: 'fldFsGMSx1058GBah',
        scheduled_day: 'fldhBYiRMKKQFR8yb',
        scheduled_date: 'fldNDBE9g9Hk39XkP',
        rules: 'fldtpHgjNy11ghWv4',
        created_by: 'fldUFIF72rGkQvy9H',
        last_scan: 'fld1DFgZ4vpcM2MSb'
    },
    // DetectionAlerts table
    alerts: {
        alert_id: 'fldNgjTZuHXBFXkh1',
        url: 'fldwGPOAUsWIwCNMn',
        account: 'fldszN7Y8jhlvWh5e',
        engine_name: 'fldjp5WpmyWUPJmmB',
        first_detected: 'fldQDrUQimH6qwS7P',
        acknowledged: 'fldQY7jwX0SclE34y',
        acknowledged_at: 'fld170gA8NwaUKPAT',
        acknowledged_by: 'fldrUOGji8nWhKgCn'
    }
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
        throw new Error(data.error?.message || `Airtable error: ${response.status}`);
    }

    return data;
}

// Helper: Get all records with field IDs
async function getAllRecords(table, filterFormula = null) {
    let allRecords = [];
    let offset = null;

    do {
        let url = `${AIRTABLE_API}/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?pageSize=100&returnFieldsByFieldId=true`;
        if (filterFormula) url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
        if (offset) url += `&offset=${offset}`;

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || 'Airtable error');

        allRecords = allRecords.concat(data.records);
        offset = data.offset;
    } while (offset);

    return allRecords;
}

// Helper: Check if a linked field contains a specific record ID
function hasLinkedRecord(linkedField, recordId) {
    if (!linkedField || !Array.isArray(linkedField)) return false;
    return linkedField.includes(recordId);
}

// Action handlers
const handlers = {
    // Find user by email in username field
    async getOrCreateUser({ email }) {
        if (!email) throw new Error('Email is required');

        console.log(`🔍 Looking for user with username = '${email}'`);
        
        // Users table is synced - READ ONLY
        // Note: filterByFormula still needs field name, but we use ID for reading
        const records = await getAllRecords(TABLES.users, `{username} = '${email}'`);
        
        if (records.length > 0) {
            console.log(`✅ Found user: ${records[0].id}`);
            return { user: records[0] };
        }

        console.log(`❌ User not found for email: ${email}`);
        return { user: null, message: 'User not found' };
    },

    // Get URLs for user - filter by linked record ID in JavaScript
    async getUrls({ userId }) {
        if (!userId) throw new Error('userId is required');

        console.log(`🔍 Getting URLs for user: ${userId}`);
        
        const F = FIELDS.urls;
        const allRecords = await getAllRecords(TABLES.urls);
        
        // Debug: log first record to see structure
        if (allRecords.length > 0) {
            console.log(`📋 Sample record fields:`, JSON.stringify(allRecords[0].fields));
            console.log(`📋 Looking for field ID: ${F.added_by}`);
        }
        
        const userRecords = allRecords.filter(r => {
            const addedBy = r.fields[F.added_by];
            const match = hasLinkedRecord(addedBy, userId);
            if (addedBy) {
                console.log(`📋 Record ${r.id}: added_by=${JSON.stringify(addedBy)}, match=${match}`);
            }
            return match;
        });
        
        console.log(`✅ Found ${userRecords.length} URLs`);
        
        const urls = userRecords.map(r => ({
            id: r.id,
            url: r.fields[F.url],
            addedAt: r.fields[F.added_at]
        }));

        return { urls };
    },

    // Add URL
    async addUrl({ userId, url }) {
        if (!userId || !url) throw new Error('userId and url are required');

        console.log(`➕ Adding URL: ${url} for user: ${userId}`);

        // Airtable requires field NAMES for writing, not IDs
        const record = await airtableRequest(TABLES.urls, 'POST', {
            fields: {
                'url': url,
                'added_by': [userId],
                'added_at': new Date().toISOString().split('T')[0]
            }
        });

        console.log(`✅ URL added: ${record.id}`);

        const F = FIELDS.urls;
        return { 
            url: { 
                id: record.id, 
                url: record.fields.url || record.fields[F.url], 
                addedAt: record.fields.added_at || record.fields[F.added_at] 
            } 
        };
    },

    // Delete URL
    async deleteUrl({ urlId }) {
        if (!urlId) throw new Error('urlId is required');

        await airtableRequest(TABLES.urls, 'DELETE', null, urlId);
        return { success: true };
    },

    // Save scan log
    async saveScanLog({ urlId, userId, status, detections, adRiskScore, resultJson }) {
        if (!urlId) throw new Error('urlId is required');

        // Airtable requires field NAMES for writing
        const fields = {
            'url': [urlId],
            'scan_timestamp': new Date().toISOString(),
            'status': status || 'unknown',
            'detections': detections || 0,
            'ad_risk_score': adRiskScore || 0,
            'result_json': resultJson || '{}'
        };

        if (userId) {
            fields['scanned_by'] = [userId];
        }

        const record = await airtableRequest(TABLES.scanLogs, 'POST', { fields });

        console.log(`✅ Scan log saved: ${record.id}`);
        return { log: record };
    },

    // Get scan logs for user's URLs
    async getScanLogs({ userId }) {
        if (!userId) throw new Error('userId is required');

        const FU = FIELDS.urls;
        const FS = FIELDS.scanLogs;

        // First get user's URLs
        const allUrls = await getAllRecords(TABLES.urls);
        const userUrls = allUrls.filter(r => hasLinkedRecord(r.fields[FU.added_by], userId));
        
        const urlIds = userUrls.map(r => r.id);
        const urlMap = {};
        userUrls.forEach(r => { urlMap[r.id] = r.fields[FU.url]; });

        if (urlIds.length === 0) {
            return { logs: [] };
        }

        // Get all scan logs and filter by user's URLs
        const allLogs = await getAllRecords(TABLES.scanLogs);
        
        const logs = allLogs
            .filter(r => {
                const logUrlIds = r.fields[FS.url] || [];
                return logUrlIds.some(id => urlIds.includes(id));
            })
            .map(r => {
                const urlId = (r.fields[FS.url] || [])[0];
                return {
                    id: r.id,
                    urlId,
                    url: urlMap[urlId] || 'Unknown',
                    timestamp: r.fields[FS.scan_timestamp],
                    status: r.fields[FS.status],
                    detections: r.fields[FS.detections] || 0,
                    adRiskScore: r.fields[FS.ad_risk_score] || 0
                };
            })
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return { logs };
    },

    // Get alerts for user - filter by account linked record
    async getAlerts({ userId }) {
        if (!userId) throw new Error('userId is required');

        const F = FIELDS.alerts;
        const allRecords = await getAllRecords(TABLES.alerts);
        const userRecords = allRecords.filter(r => hasLinkedRecord(r.fields[F.account], userId));
        
        const alerts = userRecords.map(r => ({
            id: r.id,
            urlId: (r.fields[F.url] || [])[0],
            engine: r.fields[F.engine_name],
            detected: r.fields[F.first_detected],
            acknowledged: r.fields[F.acknowledged] || false,
            acknowledgedAt: r.fields[F.acknowledged_at]
        }));

        return { alerts };
    },

    // Create alert
    async createAlert({ urlId, userId, engineName }) {
        if (!urlId || !userId || !engineName) {
            throw new Error('urlId, userId, and engineName are required');
        }

        const F = FIELDS.alerts;

        // Check for existing unacknowledged alert
        const allAlerts = await getAllRecords(TABLES.alerts);
        const existing = allAlerts.find(r => 
            hasLinkedRecord(r.fields[F.url], urlId) && 
            r.fields[F.engine_name] === engineName && 
            !r.fields[F.acknowledged]
        );

        if (existing) {
            return { alert: existing, existed: true };
        }

        // Airtable requires field NAMES for writing
        const record = await airtableRequest(TABLES.alerts, 'POST', {
            fields: {
                'url': [urlId],
                'account': [userId],
                'engine_name': engineName,
                'first_detected': new Date().toISOString(),
                'acknowledged': false
            }
        });

        return { alert: record, existed: false };
    },

    // Acknowledge alert
    async acknowledgeAlert({ alertId, userId }) {
        if (!alertId) throw new Error('alertId is required');

        // Airtable requires field NAMES for writing
        const fields = {
            'acknowledged': true,
            'acknowledged_at': new Date().toISOString()
        };

        if (userId) {
            fields['acknowledged_by'] = [userId];
        }

        const record = await airtableRequest(TABLES.alerts, 'PATCH', { fields }, alertId);

        return { alert: record };
    },

    // Get schedules for user - filter by account linked record
    async getSchedules({ userId }) {
        if (!userId) throw new Error('userId is required');

        const F = FIELDS.schedules;
        const allRecords = await getAllRecords(TABLES.schedules);
        const userRecords = allRecords.filter(r => hasLinkedRecord(r.fields[F.account], userId));
        
        const schedules = userRecords.map(r => ({
            id: r.id,
            name: r.fields[F.name] || 'Unnamed Schedule',
            frequency: r.fields[F.frequency] || 'daily',
            urlIds: r.fields[F.rules] || [],
            enabled: r.fields[F.enabled] !== false,
            lastRun: r.fields[F.last_scan],
            scheduledTime: r.fields[F.scheduled_time],
            scheduledDay: r.fields[F.scheduled_day]
        }));

        return { schedules };
    },

    // Create schedule
    async createSchedule({ userId, name, frequency, urlIds }) {
        if (!userId || !urlIds || urlIds.length === 0) {
            throw new Error('userId and urlIds are required');
        }

        // Airtable requires field NAMES for writing
        const record = await airtableRequest(TABLES.schedules, 'POST', {
            fields: {
                'name': name || `${frequency} scan`,
                'frequency': frequency || 'daily',
                'rules': JSON.stringify({ urlIds }),
                'account': [userId],
                'enabled': true
            }
        });

        return { schedule: record };
    },

    // Update schedule
    async updateSchedule({ scheduleId, enabled, name, frequency }) {
        if (!scheduleId) throw new Error('scheduleId is required');

        // Airtable requires field NAMES for writing
        const fields = {};
        if (enabled !== undefined) fields['enabled'] = enabled;
        if (name !== undefined) fields['name'] = name;
        if (frequency !== undefined) fields['frequency'] = frequency;

        const record = await airtableRequest(TABLES.schedules, 'PATCH', { fields }, scheduleId);
        return { schedule: record };
    },

    // Delete schedule
    async deleteSchedule({ scheduleId }) {
        if (!scheduleId) throw new Error('scheduleId is required');

        await airtableRequest(TABLES.schedules, 'DELETE', null, scheduleId);
        return { success: true };
    }
};

exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    if (!AIRTABLE_API_KEY) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Airtable API key not configured' })
        };
    }

    try {
        const { action, ...data } = JSON.parse(event.body);

        if (!action) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Action is required' })
            };
        }

        const handler = handlers[action];
        if (!handler) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: `Unknown action: ${action}` })
            };
        }

        console.log(`📦 v5.2 Action: ${action}`, data);
        const result = await handler(data);
        console.log(`✅ ${action} completed`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(result)
        };

    } catch (error) {
        console.error('❌ Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: error.message })
        };
    }
};
