const fs = require('fs');
const path = require('path');
const os = require('os');
const colors = require('colors');
const { Telegraf } = require('telegraf');
const axios = require('axios');
const { Readable } = require("stream")

function DisplayWarningEvent(event) {
	console.log(
		`-> Mini-WAF has protected your server now!`.white.bgRed + os.EOL +
		`   Blocked triggered event by remote IP address: ${event.request.remote_ip} at ${new Date().toLocaleString()}!`.red + os.EOL +
		`   Reason of blocking action: ${event.detectResult.Description.green}`.yellow + os.EOL +
		`   Method type: ${event.request.method.red}`.yellow + os.EOL +
		`   Malicious payload: ${(event.detectResult.PayloadDetails).red}\n`.green
	);
}

function DisplayUnhandledExceptionEvent(event) {
	console.log(
		`-> Mini-WAF has protected your server now!`.white.bgRed + os.EOL +
		`   Unhandled exception triggered at ${new Date().toLocaleString()}!`.red + os.EOL +
		`   Exception name: ${event.name.green}`.yellow + os.EOL +
		`   Exception message: ${event.message.red}`.yellow + os.EOL
	);
}

function DisplayNewConnection(req) {
	console.log(`[${(new Date()).toLocaleTimeString().cyan}] [${req.method.cyan}] [${'INFO'.green}] new connection [${String(req.remote_ip).yellow}] at ${req.path}.`);
}

function WriteEventToLog(data, result) {
	if (!fs.existsSync(path.join(__dirname, 'logs'))) {
		fs.mkdirSync(path.join(__dirname, 'logs'));
		console.log('folder created!');
	}
	const wfstream = fs.createWriteStream(path.join(__dirname, 'logs', 'ids.log'), { flags: 'a' });
	data.is_blocked = result.is_blocked;
	if(result.detect !== undefined && result.detect !== null) {
		data.detect = result.detect;
	}
	data.payload = result.payload;
	data.message = result.message;
	const readable = Readable.from(JSON.stringify(data) + '\n')
	readable.pipe(wfstream);
	wfstream.on('error', function (err) {
		console.log(err);
	});
}

async function BlockConnection(event) {
	const body = {
	  protocol: "tcp",
	  port: 80,
	  source: event.src,
	  description: event.description,
	}
	const response = await axios.post(
		'http://54.238.68.47:6969/api/iptables/inbound',
		body
	)
	console.log(response.data.data)
}

async function RedisCache(client, event) {
	let cacheTimeout = 120;
	let checkpoint = await client.get(event.request.remote_ip);
	let checkpointObj = JSON.parse(checkpoint);
	if (checkpointObj) {
		if (checkpointObj.payloadCheckpoint[event.detectResult.Type]) {
			checkpointObj.payloadCheckpoint[event.detectResult.Type] += 1;
		}
		else {
			checkpointObj.payloadCheckpoint[event.detectResult.Type] = 1;
		}
		checkpointObj.payloadCheckpoint.total += 1;
		client.set(event.request.remote_ip, JSON.stringify(checkpointObj));
		client.expire(event.request.remote_ip, cacheTimeout);
		console.log(checkpointObj);
		if (checkpointObj.payloadCheckpoint.total >= 15) {
			console.log('ip blocked!');
			client.del(event.request.remote_ip);
			BlockConnection({
				src: event.request.remote_ip, 
				description: `Block payload attack from ${event.request.remote_ip}`
			});
			WriteEventToLog(event.request, 
			{
				is_blocked: true, 
				detect: event.detectResult.Type, 
				payload: event.detectResult.PayloadDetails,
				message: 'IP has been blocked in iptables'
			});
			return BotTele({ reason: 'Blocked Attack IP!', request: event.request }, checkpointObj);
		}
		else if (checkpointObj.payloadCheckpoint.total === 10) {
			console.log('warning...');
			BotTele({ reason: 'Warning... IP is trying to attack', request: event.request }, checkpointObj);
		}
		WriteEventToLog(event.request, 
		{
			is_blocked: false, 
			detect: event.detectResult.Type, 
			payload: event.detectResult.PayloadDetails,
			message: event.detectResult.Type + ' Attack detect!'
		});
	}
	else {
		console.log('dont have cache???');
	}
}

function BotTele(event, checkpointObj) {
	const API_TOKEN = '--';
	const bot = new Telegraf(API_TOKEN);
	const chat_Id = '5258842125';
	const Phu_id = '1556668931';
	let message =
		'ip: ' + event.request.remote_ip + '\n' +
		'time: ' + new Date().toLocaleString() + '\n' +
		'description: ' + event.reason + '\n';
	for(let type in checkpointObj.payloadCheckpoint) {
		message += type + ': ' + checkpointObj.payloadCheckpoint[type] + '\n';
	}
	message += 'dos: ' + checkpointObj.ddosCheckpoint.counter;
	// console.log(message);
	bot.telegram.sendMessage(chat_Id, message.toString());
	bot.telegram.sendMessage(Phu_id, message.toString());
	//bot.launch();
	//console.log('in bot');
}

module.exports = {

	DisplayWarningEvent: DisplayWarningEvent,
	DisplayUnhandledExceptionEvent: DisplayUnhandledExceptionEvent,
	DisplayNewConnection: DisplayNewConnection,
	WriteEventToLog: WriteEventToLog,
	BlockConnection: BlockConnection,
	RedisCache: RedisCache,
	BotTele: BotTele,
}
