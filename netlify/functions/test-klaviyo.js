// Test function to send a fake URL Health Alert to Klaviyo
// This creates the metric so you can set up the flow trigger

const KLAVIYO_API_KEY = process.env.EXISCALE_KLAVIYO_KEY;

exports.handler = async (event, context) => {
    const testEmail = 'kyronhellmrich92@gmail.com'; // Your email for testing

    if (!KLAVIYO_API_KEY) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'KLAVIYO_API_KEY not configured' })
        };
    }

    try {
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
                                    email: testEmail
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
                            url: 'https://test-malicious-site.com',
                            status: 'malicious',
                            status_label: 'MALICIOUS',
                            detections: 5,
                            engines: 'Kaspersky, BitDefender, ESET, Avira, Norton',
                            engine_list: ['Kaspersky', 'BitDefender', 'ESET', 'Avira', 'Norton'],
                            dashboard_url: 'https://exiscale.com/tools/url-health/',
                            scan_time: new Date().toISOString()
                        },
                        time: new Date().toISOString()
                    }
                }
            })
        });

        const result = await response.json();

        if (response.ok) {
            return {
                statusCode: 200,
                body: JSON.stringify({ 
                    success: true, 
                    message: 'Test event sent to Klaviyo! Check Klaviyo for the "URL Health Alert" metric.',
                    email: testEmail
                })
            };
        } else {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Klaviyo error', details: result })
            };
        }

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message })
        };
    }
};
