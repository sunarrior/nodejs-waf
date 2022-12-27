// import the `Kafka` instance from the kafkajs library
const { Kafka } = require("kafkajs")
const redis = require('redis')
const signals = ['SIGTERM', 'SIGINT']

// the client ID lets kafka know who's producing the messages
const clientId = "pbl6-app"
// we can define the list of brokers in the cluster
const brokers = ["178.128.31.83:9092"]
// this is the topic to which we want to write messages
const topic = "logstash"

let client;

(async () => {
	client = redis.createClient(6379);

	client.on('error', (err) => {
    	console.log("Redis Error " + err)
	});
	await client.connect();
})();

// this is waf
const Waf = require('./wafbase');
const wafrules = require('./wafrules');

// initialize a new kafka client and initialize a producer from it
const kafka = new Kafka({ clientId, brokers });
const admin = kafka.admin();
const consumer = kafka.consumer({ groupId: clientId, rebalanceTimeout: 1000 });

signals.map(type => {
	process.on(type, async () => {
		await client.quit();
		console.log('redis closed connection');
		await consumer.disconnect();
		console.log('kafka\'s consumer closed connection');
		await admin.deleteGroups([clientId]);
		console.log(`deleted group id ${clientId}`);
		await admin.disconnect();
		console.log('kafka\'s admin closed connection');
		process.exit(0);
	});
});

const consume = async () => {
	// first, we wait for the client to connect and subscribe to the given topic
	await admin.connect();
	await consumer.connect();
	await consumer.subscribe({
		topic:topic,
	});
	await consumer.run({
		// this function is called every time the consumer gets a new message
		eachMessage: async ({ message }) => {
			// here, we just log the message to the standard output
			try {
				const data = JSON.parse(message.value).message;
				const dataJSON = JSON.parse(data);
				if(dataJSON.path !== '/index.html' && dataJSON.response_code !== '304') {
					// console.log(`received message: ${dataJSON.remote_ip}`);
					Waf.WafMiddleware(client, wafrules.Rules, dataJSON);
				}
			} catch(err) {}
		},
	})
}

module.exports = consume
