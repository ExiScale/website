// ExiScale - Get Fresh Attachment URL
// Airtable attachment URLs expire, so we fetch fresh ones on demand

const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;

exports.handler = async (event) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        // Get parameters from query string
        const { table, recordId, field } = event.queryStringParameters || {};
        
        if (!table || !recordId || !field) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Missing required parameters: table, recordId, field' })
            };
        }

        // Fetch the record from Airtable to get fresh attachment URL
        const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}/${recordId}`;
        
        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${AIRTABLE_API_KEY}`
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Airtable error:', errorText);
            return {
                statusCode: response.status,
                headers,
                body: JSON.stringify({ error: 'Failed to fetch record' })
            };
        }

        const record = await response.json();
        const attachment = record.fields[field];

        if (!attachment || !Array.isArray(attachment) || attachment.length === 0) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'No attachment found' })
            };
        }

        // Get the fresh URL from the attachment
        const freshUrl = attachment[0].url;

        // Redirect to the fresh URL
        return {
            statusCode: 302,
            headers: {
                ...headers,
                'Location': freshUrl,
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            },
            body: ''
        };

    } catch (error) {
        console.error('Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: error.message })
        };
    }
};
