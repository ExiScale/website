// URL Health - Airtable Operations Function v4
// FIXED: Linked record filtering done in JavaScript (Airtable formulas can't filter by record ID)

const AIRTABLE_API_KEY = process.env.AIRTABLE_URL_HEALTH_API_KEY;
const AIRTABLE_BASE_ID = 'appZwri4LF6oF0QSB';
const AIRTABLE_API = 'https://api.airtable.com/v0';

const TABLES = {
    users: 'Users',
    urls: 'URLs',
    scanLogs: 'ScanLogs',
    schedules: 'Schedules',
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
        throw new Error(data.error?.message || `Airtable error: ${response.status}`);
    }

    return data;
}

// Helper: Get all records (handles pagination)
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
        
        // Fetch all URLs and filter by added_by containing userId
        const allRecords = await getAllRecords(TABLES.urls);
        
        const userRecords = allRecords.filter(r => hasLinkedRecord(r.fields.added_by, userId));
        
        console.log(`✅ Found ${userRecords.length} URLs`);
        
        const urls = userRecords.map(r => ({
            id: r.id,
            url: r.fields.url,
            addedAt: r.fields.added_at
        }));

        return { urls };
    },

    // Add URL
    async addUrl({ userId, url }) {
        if (!userId || !url) throw new Error('userId and url are required');

        console.log(`➕ Adding URL: ${url} for user: ${userId}`);

        const record = await airtableRequest(TABLES.urls, 'POST', {
            fields: {
                url: url,
                added_by: [userId],
                added_at: new Date().toISOString().split('T')[0]
            }
        });

        console.log(`✅ URL added: ${record.id}`);

        return { 
            url: { 
                id: record.id, 
                url: record.fields.url, 
                addedAt: record.fields.added_at 
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

        const fields = {
            url: [urlId],
            scan_timestamp: new Date().toISOString(),
            status: status || 'unknown',
            detections: detections || 0,
            ad_risk_score: adRiskScore || 0,
            result_json: resultJson || '{}'
        };

        if (userId) {
            fields.scanned_by = [userId];
        }

        const record = await airtableRequest(TABLES.scanLogs, 'POST', { fields });

        return { log: record };
    },

    // Get scan logs for user's URLs
    async getScanLogs({ userId }) {
        if (!userId) throw new Error('userId is required');

        // First get user's URLs
        const allUrls = await getAllRecords(TABLES.urls);
        const userUrls = allUrls.filter(r => hasLinkedRecord(r.fields.added_by, userId));
        
        const urlIds = userUrls.map(r => r.id);
        const urlMap = {};
        userUrls.forEach(r => { urlMap[r.id] = r.fields.url; });

        if (urlIds.length === 0) {
            return { logs: [] };
        }

        // Get all scan logs and filter by user's URLs
        const allLogs = await getAllRecords(TABLES.scanLogs);
        
        const logs = allLogs
            .filter(r => {
                const logUrlIds = r.fields.url || [];
                return logUrlIds.some(id => urlIds.includes(id));
            })
            .map(r => {
                const urlId = (r.fields.url || [])[0];
                return {
                    id: r.id,
                    urlId,
                    url: urlMap[urlId] || 'Unknown',
                    timestamp: r.fields.scan_timestamp,
                    status: r.fields.status,
                    detections: r.fields.detections || 0,
                    adRiskScore: r.fields.ad_risk_score || 0
                };
            })
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return { logs };
    },

    // Get alerts for user - filter by account linked record
    async getAlerts({ userId }) {
        if (!userId) throw new Error('userId is required');

        const allRecords = await getAllRecords(TABLES.alerts);
        const userRecords = allRecords.filter(r => hasLinkedRecord(r.fields.account, userId));
        
        const alerts = userRecords.map(r => ({
            id: r.id,
            urlId: (r.fields.url || [])[0],
            url: r.fields.url_text || 'Unknown',
            engine: r.fields.engine_name,
            detected: r.fields.first_detected,
            acknowledged: r.fields.acknowledged || false,
            acknowledgedAt: r.fields.acknowledged_at
        }));

        return { alerts };
    },

    // Create alert
    async createAlert({ urlId, userId, engineName, urlText }) {
        if (!urlId || !userId || !engineName) {
            throw new Error('urlId, userId, and engineName are required');
        }

        // Check for existing unacknowledged alert
        const allAlerts = await getAllRecords(TABLES.alerts);
        const existing = allAlerts.find(r => 
            hasLinkedRecord(r.fields.url, urlId) && 
            r.fields.engine_name === engineName && 
            !r.fields.acknowledged
        );

        if (existing) {
            return { alert: existing, existed: true };
        }

        const record = await airtableRequest(TABLES.alerts, 'POST', {
            fields: {
                url: [urlId],
                account: [userId],
                engine_name: engineName,
                first_detected: new Date().toISOString(),
                acknowledged: false
            }
        });

        return { alert: record, existed: false };
    },

    // Acknowledge alert
    async acknowledgeAlert({ alertId, userId }) {
        if (!alertId) throw new Error('alertId is required');

        const fields = {
            acknowledged: true,
            acknowledged_at: new Date().toISOString()
        };

        if (userId) {
            fields.acknowledged_by = [userId];
        }

        const record = await airtableRequest(TABLES.alerts, 'PATCH', { fields }, alertId);

        return { alert: record };
    },

    // Get schedules for user - filter by account linked record
    async getSchedules({ userId }) {
        if (!userId) throw new Error('userId is required');

        const allRecords = await getAllRecords(TABLES.schedules);
        const userRecords = allRecords.filter(r => hasLinkedRecord(r.fields.account, userId));
        
        const schedules = userRecords.map(r => ({
            id: r.id,
            name: r.fields.name || 'Unnamed Schedule',
            frequency: r.fields.frequency || 'daily',
            urlIds: r.fields.rules || [],
            enabled: r.fields.enabled !== false,
            lastRun: r.fields.last_scan,
            scheduledTime: r.fields.scheduled_time,
            scheduledDay: r.fields.scheduled_day
        }));

        return { schedules };
    },

    // Create schedule
    async createSchedule({ userId, name, frequency, urlIds }) {
        if (!userId || !urlIds || urlIds.length === 0) {
            throw new Error('userId and urlIds are required');
        }

        const record = await airtableRequest(TABLES.schedules, 'POST', {
            fields: {
                name: name || `${frequency} scan`,
                frequency: frequency || 'daily',
                rules: JSON.stringify({ urlIds }),
                account: [userId],
                enabled: true
            }
        });

        return { schedule: record };
    },

    // Update schedule
    async updateSchedule({ scheduleId, enabled, name, frequency }) {
        if (!scheduleId) throw new Error('scheduleId is required');

        const fields = {};
        if (enabled !== undefined) fields.enabled = enabled;
        if (name !== undefined) fields.name = name;
        if (frequency !== undefined) fields.frequency = frequency;

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

        console.log(`📦 v4 Action: ${action}`, data);
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
