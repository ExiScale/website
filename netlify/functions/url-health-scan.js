// URL Health - VirusTotal Scan Function
// Keeps VirusTotal API key secure on server side

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const API_BASE = 'https://www.virustotal.com/api/v3';
const POLL_INTERVAL = 5000;
const MAX_ATTEMPTS = 12;

// Ad-impact vendor weights
const WEIGHT_MAP = {
    "Google Safebrowsing": 10,
    "Fortinet": 9,
    "PhishTank": 8,
    "OpenPhish": 8,
    "BitDefender": 7,
    "ESET": 7,
    "Kaspersky": 7,
    "Sophos": 7,
    "McAfee": 6,
    "TrendMicro": 6,
    "Symantec": 6,
    "Avast": 6,
    "AVG": 6,
    "Comodo": 5,
    "Netcraft": 5,
    "Spamhaus": 5,
    "CRDF": 5,
    "CyRadar": 5
};

// Helper to delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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

    // Only allow POST
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    // Check API key
    if (!VIRUSTOTAL_API_KEY) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'VirusTotal API key not configured' })
        };
    }

    try {
        const { url } = JSON.parse(event.body);

        if (!url) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'URL is required' })
            };
        }

        console.log(`🔍 Scanning URL: ${url}`);

        // Step 1: Submit URL to VirusTotal
        const submitResponse = await fetch(`${API_BASE}/urls`, {
            method: 'POST',
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        if (!submitResponse.ok) {
            const errorText = await submitResponse.text();
            console.error('Submit error:', errorText);
            throw new Error('Failed to submit URL to VirusTotal');
        }

        const submitData = await submitResponse.json();
        const analysisId = submitData.data.id;
        console.log(`📝 Analysis ID: ${analysisId}`);

        // Step 2: Poll for results
        let analysisData;
        for (let i = 0; i < MAX_ATTEMPTS; i++) {
            await delay(POLL_INTERVAL);

            const checkResponse = await fetch(`${API_BASE}/analyses/${analysisId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });

            if (!checkResponse.ok) {
                console.error('Check error:', await checkResponse.text());
                continue;
            }

            analysisData = await checkResponse.json();
            
            if (analysisData.data.attributes.status === 'completed') {
                console.log('✅ Scan completed');
                break;
            }

            console.log(`⏳ Waiting... (${i + 1}/${MAX_ATTEMPTS})`);
        }

        if (!analysisData || analysisData.data.attributes.status !== 'completed') {
            throw new Error('Scan did not complete in time');
        }

        // Step 3: Process results
        const stats = analysisData.data.attributes.stats;
        const detections = (stats.malicious || 0) + (stats.suspicious || 0);
        const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

        // Determine verdict
        let verdict = 'clean';
        if (detections >= 5) verdict = 'malicious';
        else if (detections > 0) verdict = 'suspicious';

        const verdictExplanation = 
            verdict === 'clean' ? 'No vendors flagged this URL.' :
            verdict === 'suspicious' ? 'A few vendors flagged this as suspicious.' :
            'Multiple vendors detected malware or phishing behavior.';

        // Get malicious engines
        const allResults = analysisData.data.attributes.results;
        const maliciousEngines = Object.entries(allResults)
            .filter(([_, r]) => r.category === 'malicious')
            .map(([engine]) => engine);

        const suspiciousEngines = Object.entries(allResults)
            .filter(([_, r]) => r.category === 'suspicious')
            .map(([engine]) => engine);

        // Calculate ad-impact score
        const flaggedByAdVendors = maliciousEngines.filter(engine =>
            Object.keys(WEIGHT_MAP).some(v => 
                engine.toLowerCase().includes(v.toLowerCase())
            )
        );

        const adRiskScore = flaggedByAdVendors.reduce((sum, engine) => {
            const vendor = Object.keys(WEIGHT_MAP).find(v => 
                engine.toLowerCase().includes(v.toLowerCase())
            );
            return sum + (WEIGHT_MAP[vendor] || 3);
        }, 0);

        let adImpactRisk = 'safe';
        if (adRiskScore >= 16) adImpactRisk = 'block-risk';
        else if (adRiskScore >= 9) adImpactRisk = 'moderate';
        else if (adRiskScore > 0) adImpactRisk = 'review';

        const lastScanDate = new Date(
            analysisData.data.attributes.date * 1000
        ).toISOString();

        // Build response
        const result = {
            url,
            verdict,
            verdictExplanation,
            detections,
            totalEngines,
            lastScanDate,
            maliciousEngines,
            suspiciousEngines,
            flaggedByAdVendors,
            adRiskScore,
            adImpactRisk,
            hasAdImpact: adImpactRisk !== 'safe',
            stats,
            fullResults: allResults  // Include all engine results for detailed display
        };

        console.log(`📊 Result: ${verdict} (${detections} detections, ad risk: ${adRiskScore})`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(result)
        };

    } catch (error) {
        console.error('❌ Scan error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                error: error.message,
                verdict: 'error'
            })
        };
    }
};
