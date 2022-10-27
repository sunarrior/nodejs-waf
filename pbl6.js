const {WAFNodejs} = require('./waf')

const baseConfig = {
    allowedMethods: ['GET', 'POST', 'PATCH', 'DELETE'], // allowed / desired HTTP methods
    contentTypes: ['application/json', 'multipart/form-data'], // allowed / desired content-type
    enabledCheck: {
        'sqlInjection': true
    }
}

const _waf = new WAFNodejs(baseConfig)

request = {
    headers: {
        'x-forwarded-for': "127.0.0.1' or 1=1#",
        'user-agent': "aaa' or 1/*",
    }
}

if((result = _waf.sqlInjectionCheck(request)).state) {
    console.log(result.msg)
} else {
    console.log(result.msg)
}