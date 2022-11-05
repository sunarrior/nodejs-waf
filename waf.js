// This project is coded base on https://github.com/undertuga/WAF-JS
/*******************************************************************
A. Properties of WAFNodejs
*** 1. allowedMethods: request method is allowed for communication
*** 2. allowedContentTypes: content type is allowed for data transfer
B. Methods of WAFNodejs
*******************************************************************/

// Import regex module
const {regexSQL} = require('./regexInit')

class wafnodejs {

    constructor(config) {
        this.allowedMethods = config.allowedMethods
        this.allowedContentTypes = config.contentType
        this.enabledCheck = config.enabledCheck
    }

    requestCheck(requestMethod, contentType) {
        return !(
            this.allowedMethods.indexOf(requestMethod) < 0 && 
            this.allowedContentTypes.indexOf(contentType) < 0
        )
    }

    sqlInjectionCheck(request) {
        /***************************** 
        A. Check in headers
        *** 1. x-forwarded-for
        *** 2. user-agent
        *** 3. referer (dev)
        *****************************/
        let state = false
        let msg = ''

        if(this.enabledCheck['sqlInjection']) {
            if(regexSQL(request.headers['x-forwarded-for'])) {
                state = true
                msg += 'SQLi detected on x-forwarded-for'+'\n'
            } 
            if(regexSQL(request.headers['user-agent'])) {
                state = true
                msg += 'SQLi detected on user-agent'+'\n'
            }
            for(const prop of Object.keys(request.body)) {
                if(regexSQL(request.body[prop])) {
                    msg += `SQLi detected on ${prop}`;
                    state = true;
                }
            }
            if(msg === '') {
                state = false
                msg += 'SQLi not detected'
            }
        } else {
            state = false
            msg += 'SQLi check is not enabled'
        }
        return {state: state, msg: msg}
    }

    xssCheck() {

    }

    pathTraversalCheck() {

    }

    wafChecks(req) {
        if(this.requestCheck(req.method, req.headers['content-type'])) {

        }

        // if(this.sqlInjectionCheck()) {

        // }
    }
}

module.exports.WAFNodejs = wafnodejs