const child = require('child_process')

module.exports = (app) => {
    return {
        deleteInboundRule: (req, res) => {
            deletedRule(req, res, command = 'iptables -D chain-inbound-rules')
        },
        deleteOutboundRule: (req, res) => {
            deletedRule(req, res, command = 'iptables -D chain-outbound-rules')
        }
    }
}

function deletedRule(req, res, command){
    try {
        const data = req.body
        command = command + ' ' + data.number
        child.exec(command, (error, stdout, stderr) => {
            
            if (error) {
                return res.status(500).send({
                    ok: false,
                    message: 'Internal server error!',
                    error
                })
            }
    
            return res.status(200).send({
                data: {
                    ok: true,
                    stdout,
                    stderr
                }
            })
        })
        
    } catch (error) {
        return res.json({
            data: {
                ok: false,
                command,
                message: 'Internal server error!',
                error
            }
        })
    }
}