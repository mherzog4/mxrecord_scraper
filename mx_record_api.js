import express from 'express';
import dns from 'dns';
import { promisify } from 'util';

const app = express();
const port = process.env.PORT || 3000;

// Promisify the dns.resolveMx function
const resolveMx = promisify(dns.resolveMx);

app.use(express.json());

app.post('/check-mx', async (req, res) => {
    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
    }

    try {
        const mxRecords = await resolveMx(domain);
        const mxRecord = mxRecords[0].exchange.toLowerCase();
        const mxProvider = determineEmailProvider(mxRecord);
        const mxSecurityGateway = determineEmailSecurity(mxRecord);

        res.json({
            domain,
            mx_record: mxRecord,
            mx_provider: mxProvider,
            mx_security_gateway: mxSecurityGateway
        });
    } catch (error) {
        console.error('Error resolving MX records:', error);
        res.status(500).json({ error: 'Failed to resolve MX records' });
    }
});

function determineEmailProvider(mxRecord) {
    if (mxRecord.includes('google') || mxRecord.includes('gmail')) {
        return 'Google Workspace';
    } else if (mxRecord.includes('outlook') || mxRecord.includes('microsoft')) {
        return 'Microsoft 365';
    } else if (mxRecord.includes('gslb.pphosted.com') || mxRecord.includes('ppe-hosted.com')) {
        return 'Proofpoint';
    } else if (mxRecord.includes('iphmx.com')) {
        return 'Cisco Email Security';
    } else if (mxRecord.includes('mimecast.com')) {
        return 'Mimecast';
    } else {
        return 'Unknown';
    }
}

function determineEmailSecurity(mxRecord) {
    const securityGateways = [
        'proofpoint',
        'pphosted.com',
        'ppe-hosted.com',
        'barracuda',
        'mimecast',
        'iphmx.com'
    ];

    return securityGateways.some(gateway => mxRecord.includes(gateway));
}

app.listen(port, () => {
    console.log(`MX Record API listening on port ${port}`);
});
