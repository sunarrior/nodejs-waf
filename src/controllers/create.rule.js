const child = require('child_process')

module.exports = (app) => {  
    return {
        createInboundRule: (req, res) => {
            addRule(req, res, command = 'iptables -A chain-inbound-rules')
        },
        createOutboundRule: (req, res) => {
            addRule(req, res, command = 'iptables -A chain-outbound-rules')
        }
    }
}

function addRule(req, res, command) {
    try {
        const data = req.body

        protocol = data.protocol
        port = data.port
        source = data.source
        description = data.description

        // Check protocol valid syntax
        if ( protocol !== null && protocol !== undefined) {
            if (protocol === 'tcp' || protocol === 'udp' || protocol === 'icmp') {
                command += ' -p ' + protocol
            }
        }

        // Check port valid syntax
        if ( port !== null && port !== undefined) {
            if (protocol === 'tcp' || protocol === 'udp') {
                if (typeof port === 'number') {
                    command += ' --dport ' + port
                } else if (typeof port === 'string') {
                    port = port.replace(/ /g,'').replace(/-/g,':')
                    command += ' --dport ' + port
                }
            }
        }

        // Check source valid syntax
        if ( source !== null && source !== undefined) {
            if (typeof source === 'string') {
                let CIDR = /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/igm;
                if (source.match(CIDR)) {
                    ipFormat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
                    let ip = source.split('/')[0]
                    if (ip.match(ipFormat)) {
                        command += ' -s ' + source
                    }
                }
            }
        }

        // Check description valid syntax
        if ( description !== null && description !== undefined) {
            if ((protocol !== undefined && protocol !== null) || (source !== undefined && source !== null)) {
                command += ' -m comment --comment "' + description + '"'
            }
        }

        command += ' -j ACCEPT' 

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
                message: 'Internal server error!'
            }
        })
    } 
}