// Netlify Serverless Function - Airtable API Proxy
// This keeps your API key secret on the server

const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;

exports.handler = async (event, context) => {
    // Set CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        // Parse the request body
        let body;
        if (event.isBase64Encoded) {
            body = JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'));
        } else {
            body = JSON.parse(event.body || '{}');
        }
        const { action, table, params, filterFormula } = body;

        if (!table) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Table name is required' })
            };
        }

        // Build Airtable URL
        let url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}`;

        // Add query parameters
        const queryParams = new URLSearchParams();
        if (filterFormula) {
            queryParams.append('filterByFormula', filterFormula);
        }
        if (params) {
            Object.entries(params).forEach(([key, value]) => {
                queryParams.append(key, value);
            });
        }

        if (queryParams.toString()) {
            url += '?' + queryParams.toString();
        }

        // Make request to Airtable
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (!response.ok) {
            return {
                statusCode: response.status,
                headers,
                body: JSON.stringify({ error: data.error || 'Airtable API error' })
            };
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(data)
        };

    } catch (error) {
        console.error('Function error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                error: 'Internal server error',
                message: error.message,
                stack: error.stack,
                env_check: {
                    hasApiKey: !!AIRTABLE_API_KEY,
                    hasBaseId: !!AIRTABLE_BASE_ID
                }
            })
        };
    }
};














