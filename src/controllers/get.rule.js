const child = require('child_process')

module.exports = (app) => {
    return {
        getInboundRule: (req, res) => {
            getChainRules(res, command = 'iptables -L chain-inbound-rules -n --line-numbers')
        },
        getOutboundRule: (req, res) => {
            getChainRules(res, command = 'iptables -L chain-outbound-rules -n --line-numbers')
        },
    }
}

function getChainRules(res, command) {
    try {
        child.exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).send({
                    message: 'Internal server error!',
                    error
                })
            }

            return res.status(200).send({
                data: {
                    stdout: stdout.split('\n'),
                    stderr
                }
            })
        })
    } catch (error) {
        return res.status(500).send({
            message: 'Internal server error!',
            error
        })
    }
}