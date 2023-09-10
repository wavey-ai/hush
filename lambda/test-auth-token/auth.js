const { Authenticator } = require('cognito-at-edge');

const authenticator = new Authenticator({
  region: '',
  userPoolId: '',
  userPoolAppId: '',
  userPoolAppSecret: '',
  userPoolDomain: '',
  logLevel: 'trace',
  allowCookieSubdomains: true,
  apiVersion: '',
});

exports.handler = async function(event) {
  const { request } = event.Records[0].cf;
  if (request.method === 'OPTIONS') {
    const originHeader = request.headers.origin && request.headers.origin[0]?.value;
    const response = {
      status: '200',
      statusDescription: 'OK',
      headers: {
        'access-control-allow-origin': [{
          key: 'Access-Control-Allow-Origin',
          value: originHeader || '*',
        }],
        'access-control-allow-methods': [{
          key: 'Access-Control-Allow-Methods',
          value: 'GET, OPTIONS',
        }],
        'access-control-allow-headers': [{
          key: 'Access-Control-Allow-Headers',
          value: 'Content-Type, Authorization',
        }],
        'access-control-max-age': [{
          key: 'Access-Control-Max-Age',
          value: '86400',
        }],
      },
    };
    return response;
  } else {
    return authenticator.handle(event);
  }
};
