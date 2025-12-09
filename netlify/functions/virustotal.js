// netlify/functions/virustotal.js
// VirusTotal API Proxy for URL Health Checker

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_API_BASE = 'https://www.virustotal.com/api/v3';

exports.handler = async (event, context) => {
    // CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight
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

    // Check API key is configured
    if (!VIRUSTOTAL_API_KEY) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'VirusTotal API key not configured' })
        };
    }

    try {
        const { action, url, analysisId } = JSON.parse(event.body);

        if (!action || !url) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Missing action or url parameter' })
            };
        }

        // Clean the URL - ensure it has protocol
        let cleanUrl = url.trim();
        if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
            cleanUrl = 'http://' + cleanUrl;
        }

        if (action === 'scan') {
            // Submit URL for scanning
            const formData = new URLSearchParams();
            formData.append('url', cleanUrl);

            const scanResponse = await fetch(`${VT_API_BASE}/urls`, {
                method: 'POST',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: formData.toString()
            });

            if (!scanResponse.ok) {
                const errorText = await scanResponse.text();
                console.error('VT Scan Error:', scanResponse.status, errorText);
                return {
                    statusCode: scanResponse.status,
                    headers,
                    body: JSON.stringify({ 
                        error: 'VirusTotal scan failed', 
                        status: scanResponse.status,
                        details: errorText
                    })
                };
            }

            const scanData = await scanResponse.json();
            
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    analysisId: scanData.data?.id,
                    data: scanData
                })
            };

        } else if (action === 'report') {
            // Get URL report using URL identifier (base64 of URL without padding)
            const urlId = Buffer.from(cleanUrl).toString('base64').replace(/=/g, '');
            
            const reportResponse = await fetch(`${VT_API_BASE}/urls/${urlId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });

            if (reportResponse.status === 404) {
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        success: true,
                        notFound: true,
                        message: 'URL not in database, scan required'
                    })
                };
            }

            if (!reportResponse.ok) {
                const errorText = await reportResponse.text();
                console.error('VT Report Error:', reportResponse.status, errorText);
                return {
                    statusCode: reportResponse.status,
                    headers,
                    body: JSON.stringify({ 
                        error: 'VirusTotal report failed', 
                        status: reportResponse.status 
                    })
                };
            }

            const reportData = await reportResponse.json();
            
            // Extract relevant stats
            const stats = reportData.data?.attributes?.last_analysis_stats || {};
            
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const harmless = stats.harmless || 0;
            const undetected = stats.undetected || 0;
            const total = malicious + suspicious + harmless + undetected;
            
            // Calculate risk score
            const riskScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;
            
            // Determine status
            let status = 'clean';
            if (malicious > 0) {
                status = 'malicious';
            } else if (suspicious > 0) {
                status = 'suspicious';
            }

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    url: url,
                    status: status,
                    stats: { malicious, suspicious, harmless, undetected, total },
                    riskScore: riskScore,
                    detections: malicious + suspicious,
                    lastAnalysisDate: reportData.data?.attributes?.last_analysis_date,
                    categories: reportData.data?.attributes?.categories || {}
                })
            };

        } else if (action === 'analysis') {
            // Check analysis status
            if (!analysisId) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Missing analysisId' })
                };
            }

            const analysisResponse = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });

            if (!analysisResponse.ok) {
                return {
                    statusCode: analysisResponse.status,
                    headers,
                    body: JSON.stringify({ error: 'Analysis check failed' })
                };
            }

            const analysisData = await analysisResponse.json();

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    status: analysisData.data?.attributes?.status,
                    stats: analysisData.data?.attributes?.stats || {}
                })
            };

        } else {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Invalid action. Use: scan, report, or analysis' })
            };
        }

    } catch (error) {
        console.error('Function error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Internal server error', message: error.message })
        };
    }
};
