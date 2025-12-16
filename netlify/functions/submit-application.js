// Netlify Function: submit-application.js
// Place this in: netlify/functions/submit-application.js

exports.handler = async (event, context) => {
    // CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle CORS preflight request
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    // Only allow POST
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        const data = JSON.parse(event.body);
        
        // Map form fields to Airtable field names (EXACTLY matching Airtable columns)
        const fields = {
            // Screening
            "US Citizen": data.us_citizen || null,
            "Has ITIN": data.itin || null,
            "US Presence": data.us_presence || null,
            "Has CB Provider": data.chargeback_provider || null,
            "CB Provider Name": data.chargeback_provider_name || null,
            "CB Provider Website": data.chargeback_provider_website || null,
            
            // Business Information
            "Legal Business Name": data.legal_business_name || null,
            "DBA Name": data.dba_name || null,
            "Legal Address": data.legal_address || null,
            "Legal City": data.legal_city || null,
            "Legal State": data.legal_state || null,
            "Legal Zip": data.legal_zip || null,
            "Business Phone": data.business_phone || null,
            "Customer Service Phone": data.customer_service_phone || null,
            "Fax Number": data.fax || null,
            "Contact Email": data.contact_email || null,
            "Contact Name": data.contact_name || null,
            "EIN": data.ein || null,
            "Website": data.website || null,
            "Number Of Locations": data.locations ? data.locations.toString() : null,
            "Average Ticket": data.avg_ticket || null,
            "Monthly Volume": data.monthly_volume || null,
            "Products / Services": data.products_services || null,
            "Keyed": data.percent_keyed || null,
            "Swiped": data.percent_swiped || null,
            "Equipment Software": data.equipment || null,
            "Business Type": data.business_type || null,
            "Business Start Date": data.business_start_date || null,
            "Sale Method": data.sale_method ? (Array.isArray(data.sale_method) ? data.sale_method.join(', ') : data.sale_method) : null,
            
            // Principal Information (Note: Airtable uses "Principle" spelling)
            "Principle First Name": data.principal_first_name || null,
            "Principle Middle Initial": data.principal_middle || null,
            "Principle Last Name": data.principal_last_name || null,
            "Principle Address": data.principal_address || null,
            "Principle City": data.principal_city || null,
            "Principle State": data.principal_state || null,
            "Principle Zip": data.principal_zip || null,
            "Principle Phone Number": data.principal_phone || null,
            "Principle Email": data.principal_email || null,
            "Principle DOB": data.principal_dob || null,
            "Principle Licence": data.principal_license || null,
            "Ownership Percent": data.ownership_percent || null,
            "Controlling Individual": data.controlling_individual || null,
            "Country Of Origin": data.country_origin || null,
            
            // Bank Information
            "Bank Account Name": data.bank_account_name || null,
            "Bank Name": data.bank_name || null,
            "Bank Phone": data.bank_phone || null,
            "Routing Number": data.routing_number || null,
            "Account Number": data.account_number || null,
            "SSN": data.ssn || null,
            
            // MOTO Questionnaire
            "Product Description": data.product_description || null,
            "Purchase Method": data.purchase_method || null,
            "Has Store Front": data.has_storefront || null,
            "Delivery Timeframe": data.delivery_timeframe || null,
            "Refund Policy": data.refund_policy || null,
            "Percent Deposits Future Services": data.percent_deposits || null,
            "Percent Cash & Carry": data.percent_cash_carry || null,
            "Geographic Area": data.geographic_area || null,
            "Percent International Sales": data.percent_international || null,
            "Product Owner": data.product_owner || null,
            "Percent Sales Consumer": data.percent_consumer || null,
            "Percent Sales Business": data.percent_business || null,
            "Fulfillment House Name": data.fulfillment_name || null,
            "Fulfillment House Address": data.fulfillment_address || null,
            "Fulfillment House Number": data.fulfillment_phone || null,
            "Payment Point": data.payment_point || null,
            "Ship Time After Authorization": data.ship_time || null,
            "Shipping Service": data.shipping_service || null,
            "Delivery Receipt Required": data.delivery_receipt || null,
            "Advertising Method": data.advertising || null,
            "Requires Deposit": data.requires_deposit || null,
            "Deposit Amount": data.deposit_amount || null,
            "Warranty Guarantee": data.warranty || null,
            "Previous Processing": data.previous_processing || null,
            "Business Seasonal": data.seasonal || null,
            "Recurring Transactions": data.recurring || null,
            "Product Stored At Business": data.product_stored || null,
            "Order Processor": data.order_processor || null
            
            // Note: File upload fields (Bank Statements, Processing Statements, ID / Passport) 
            // require separate file upload handling - not implemented yet
        };

        // Remove null/undefined/empty values (Airtable doesn't like them)
        Object.keys(fields).forEach(key => {
            if (fields[key] === null || fields[key] === undefined || fields[key] === '') {
                delete fields[key];
            }
        });

        console.log('Submitting to Airtable:', JSON.stringify(fields, null, 2));

        // Submit to Airtable
        const response = await fetch(
            `https://api.airtable.com/v0/${process.env.AIRTABLE_BASE_ID_PP}/Merchant%20Applications`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${process.env.AIRTABLE_API_KEY_PP}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ fields })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            console.error('Airtable error:', JSON.stringify(result, null, 2));
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Failed to submit application', 
                    details: result,
                    fieldsAttempted: Object.keys(fields)
                })
            };
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: 'Application submitted successfully',
                recordId: result.id 
            })
        };

    } catch (error) {
        console.error('Server error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Server error', message: error.message })
        };
    }
};
