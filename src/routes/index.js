const routes = require('express').Router()

module.exports = (app) => {
    
    /* ===== IPTABLES ROUTES ===== */
    const getController = require('../controllers/get.rule')(app)
    const createController = require('../controllers/create.rule')(app)
    const deleteController = require('../controllers/delete.rule')(app)
    const updateController = require('../controllers/edit.rule')(app)

    // Rules inbound routes
    routes.get('/iptables/inbound', getController.getInboundRule)
    routes.post('/iptables/inbound', createController.createInboundRule)
    routes.put('/iptables/inbound', updateController.updateInboundRule)
    routes.delete('/iptables/inbound', deleteController.deleteInboundRule)

    // Rules outbound routes
    routes.get('/iptables/outbound', getController.getOutboundRule)
    routes.post('/iptables/outbound', createController.createOutboundRule)
    routes.put('/iptables/outbound', updateController.updateOutboundRule)
    routes.delete('/iptables/outbound', deleteController.deleteOutboundRule)

    return routes
}