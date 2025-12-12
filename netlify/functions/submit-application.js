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
        
        // Map form fields to Airtable field names
        const fields = {
            // Screening
            "US Citizen": data.us_citizen || null,
            "Has ITIN": data.itin || null,
            "US Presence": data.us_presence || null,
            "Has Chargeback Provider": data.chargeback_provider || null,
            "Chargeback Provider Name": data.chargeback_provider_name || null,
            "Chargeback Provider Website": data.chargeback_provider_website || null,
            "Chargeback Provider Email": data.chargeback_provider_email || null,
            
            // Business Information
            "Legal Business Name": data.legal_business_name || null,
            "DBA Name": data.dba_name || null,
            "Legal Address": data.legal_address || null,
            "Legal City": data.legal_city || null,
            "Legal State": data.legal_state || null,
            "Legal Zip": data.legal_zip || null,
            "DBA Address": data.dba_address || null,
            "DBA City": data.dba_city || null,
            "DBA State": data.dba_state || null,
            "DBA Zip": data.dba_zip || null,
            "Business Phone": data.business_phone || null,
            "Customer Service Phone": data.customer_service_phone || null,
            "Fax": data.fax || null,
            "Contact Email": data.contact_email || null,
            "Contact Name": data.contact_name || null,
            "EIN": data.ein || null,
            "Website": data.website || null,
            "Number of Locations": data.locations ? parseInt(data.locations) : null,
            "Average Ticket": data.avg_ticket ? parseFloat(data.avg_ticket.replace(/[^0-9.]/g, '')) : null,
            "Monthly Volume": data.monthly_volume ? parseFloat(data.monthly_volume.replace(/[^0-9.]/g, '')) : null,
            "Products Services": data.products_services || null,
            "Percent Keyed": data.percent_keyed ? parseFloat(data.percent_keyed) : null,
            "Percent Swiped": data.percent_swiped ? parseFloat(data.percent_swiped) : null,
            "Equipment Software": data.equipment || null,
            "Business Type": data.business_type || null,
            "Business Start Date": data.business_start_date || null,
            "Sale Method": data.sale_method ? (Array.isArray(data.sale_method) ? data.sale_method : [data.sale_method]) : null,
            
            // Principal Information
            "Principle First Name": data.principal_first_name || null,
            "Principle Last Name": data.principal_last_name || null,
            "Principle Middle Initial": data.principal_middle || null,
            "Principle Address": data.principal_address || null,
            "Principle City": data.principal_city || null,
            "Principle State": data.principal_state || null,
            "Principle Zip": data.principal_zip || null,
            "Principle Phone": data.principal_phone || null,
            "Principle Email": data.principal_email || null,
            "Principle DOB": data.principal_dob || null,
            "Principle License": data.principal_license || null,
            "Ownership Percent": data.ownership_percent ? parseFloat(data.ownership_percent) : null,
            "Controlling Individual": data.controlling_individual || null,
            "Country of Origin": data.country_origin || null,
            
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
            "Has Storefront": data.has_storefront || null,
            "Delivery Timeframe": data.delivery_timeframe || null,
            "Refund Policy": data.refund_policy || null,
            "Percent Deposits Future Service": data.percent_deposits ? parseFloat(data.percent_deposits) : null,
            "Percent Cash and Carry": data.percent_cash_carry ? parseFloat(data.percent_cash_carry) : null,
            "Geographic Area": data.geographic_area || null,
            "Percent International Sales": data.percent_international ? parseFloat(data.percent_international) : null,
            "Product Owner": data.product_owner || null,
            "Percent Sales Consumer": data.percent_consumer ? parseFloat(data.percent_consumer) : null,
            "Percent Sales Business": data.percent_business ? parseFloat(data.percent_business) : null,
            "Fulfillment House Name": data.fulfillment_name || null,
            "Fulfillment House Address": data.fulfillment_address || null,
            "Fulfillment House Phone": data.fulfillment_phone || null,
            "Payment Point": data.payment_point || null,
            "Ship Time After Authorization": data.ship_time || null,
            "Shipping Service": data.shipping_service || null,
            "Delivery Receipt Required": data.delivery_receipt || null,
            "Advertising Method": data.advertising || null,
            "Requires Deposit": data.requires_deposit || null,
            "Deposit Amount": data.deposit_amount ? parseFloat(data.deposit_amount.replace(/[^0-9.]/g, '')) : null,
            "Warranty Guarantee": data.warranty || null,
            "Previous Processing": data.previous_processing || null,
            "Business Seasonal": data.seasonal || null,
            "Recurring Transactions": data.recurring || null,
            "Product Stored at Business": data.product_stored || null,
            "Order Processor": data.order_processor || null,
            
            // Status
            "Status": "New"
        };

        // Remove null values
        Object.keys(fields).forEach(key => {
            if (fields[key] === null || fields[key] === undefined || fields[key] === '') {
                delete fields[key];
            }
        });

        // Submit to Airtable
        const response = await fetch(
            `https://api.airtable.com/v0/${process.env.AIRTABLE_PAYMENT_PROCESSING_BASE_ID}/${process.env.AIRTABLE_PAYMENT_PROCESSING_TABLE_ID}`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${process.env.AIRTABLE_PAYMENT_PROCESSING_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ fields })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            console.error('Airtable error:', result);
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Failed to submit application', details: result })
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
