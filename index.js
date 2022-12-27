const consume = require("./app")

// start the consumer, and log any errors
consume().catch((err) => {
	console.error("error in consumer: ", err)
})
