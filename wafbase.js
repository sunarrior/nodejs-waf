const wafutils = require('./wafutils');
const util = require('util');

//---------------------------------------------------------------------------

const WAF_MATCH_TYPE = {
	MATCH_METHOD_TYPE: 0x01,
	MATCH_USER_AGENT: 0x02,
	MATCH_HEADERS: 0x04,
	MATCH_QUERY_STRING: 0x08,
	MATCH_BODY: 0x10,
	MATCH_FILE_EXT: 0x20,
}

//---------------------------------------------------------------------------
async function WafMiddleware(client, wafObj, req) {
	let WafEngine = function (wafObj, req) {
		let originReq = {...req};
		req.headers = {
			'Path': req.path,
			'X-Forwarded-For': req.x_forward_for,
			'Referrer': req.http_referrer,
		};
		let WarningStatus = false;
		let DetectResult = {
			PayloadDetails: null,
			Description: null,
			Type: null
		};

		let WafRule = wafObj;

		let MethodTypesMatchStatus = false;
		let UserAgentsMatchStatus = false;
		let HeadersMatchStatus = false;
		let QueryStringsMatchStatus = false;
		let BodysMatchStatus = false;

		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_METHOD_TYPE)) {
			let MethodTypes = WafRule.MethodTypes.split('|');
			for (let j = 0; j < MethodTypes.length; j++) {
				if (req.method.toUpperCase() == MethodTypes[j].replace(/\s/g, '').toUpperCase()) {
					MethodTypesMatchStatus = true;
					break;
				}
			}
		}
		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_USER_AGENT)) {
			const decodeUG = decodeURIComponent(req.http_user_agent);
			for (let x = 0; x < WafRule.UserAgents.length; x++) {
				for (let category of Object.keys(WafRule.UserAgents[x].REGEX)) {
					// console.log((new RegExp(WafRule.UserAgents[x].REGEX[category].RE).test(req.http_user_agent)))
					if ((new RegExp(WafRule.UserAgents[x].REGEX[category].RE).test(decodeUG))) {
						UserAgentsMatchStatus = true;
						DetectResult.PayloadDetails = decodeUG;
						DetectResult.Description =  WafRule.UserAgents[x].REGEX[category].DSC + " [UserAgents]";
						DetectResult.Type = WafRule.UserAgents[x].TYPE;
						break;
					}
				}
			}
		}
		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_HEADERS)) {
			let breakLoop = false;
			for (let x = 0; x < WafRule.Headers.length; x++) {
				if(breakLoop) {break;}
				for (let category of Object.keys(WafRule.Headers[x].REGEX)) {
					if(breakLoop) {break;}
					for (let header in req.headers) {
						let decodeHD = decodeURIComponent(req.headers[header]);
						if ((new RegExp(WafRule.Headers[x].REGEX[category].RE).test(decodeHD))) {
							HeadersMatchStatus = true;
							DetectResult.PayloadDetails = decodeHD;
							DetectResult.Description = WafRule.Headers[x].REGEX[category].DSC + " [Headers]";
							DetectResult.Type = WafRule.Headers[x].TYPE;
							breakLoop = true;
							break;
						}
					}
				}
			}
		}
		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_QUERY_STRING)) {
			let breakLoop = false;
			decodedQuery = decodeURIComponent(req.request_query);
			for (let x = 0; x < WafRule.QueryStrings.length; x++) {
				if(breakLoop) {break;}
				for (let category of Object.keys(WafRule.QueryStrings[x].REGEX)) {
					if (new RegExp(WafRule.QueryStrings[x].REGEX[category].RE).test(decodedQuery)) {
						QueryStringsMatchStatus = true;
						DetectResult.PayloadDetails = req.request_query;
						DetectResult.Description = WafRule.QueryStrings[x].REGEX[category].DSC + " [QueryStrings]";
						DetectResult.Type = WafRule.QueryStrings[x].TYPE;
						breakLoop = true;
						break;
					}
				}
			}

		}	
		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_FILE_EXT)) {
			const FileName = (req.request_body).match(WafRule.UploadFile.REGEX.UPLOAD_FILE.RE);
			if(FileName !== undefined && FileName !== null) {
				BodysMatchStatus = true;
				DetectResult.PayloadDetails = "File name: " + FileName;
				DetectResult.Description = WafRule.UploadFile.REGEX.UPLOAD_FILE.DSC + " [Bodys]";
				DetectResult.Type = WafRule.UploadFile.TYPE;
			}
		}
		if (WafCheckFlags(WafRule.MatchTypes, WAF_MATCH_TYPE.MATCH_BODY) && !BodysMatchStatus) {
			breakLoop = false;
			let decodeBD = decodeURIComponent(req.request_body);
			for (let x = 0; x < WafRule.Bodys.length; x++) {
				if(breakLoop) {break;}
				for(let category of Object.keys(WafRule.Bodys[x].REGEX)) {
					if ((new RegExp(WafRule.Bodys[x].REGEX[category].RE)).test(decodeBD)) {
						BodysMatchStatus = true;
						DetectResult.PayloadDetails = decodeBD;
						DetectResult.Description = WafRule.Bodys[x].REGEX[category].DSC + " [Bodys]";
						DetectResult.Type = WafRule.Bodys[x].TYPE;
						breakLoop = true;
						break;
					}
				}
			}
		}
		
		//------------------------------------------------------------------------------

		let Assertions = [
			MethodTypesMatchStatus,
			UserAgentsMatchStatus,
			HeadersMatchStatus,
			QueryStringsMatchStatus,
			BodysMatchStatus,
		];
		if (WafCheckAssertions(Assertions)) {
			//Warning the request.
			WarningStatus = true;
		}

		if (!WarningStatus){
			//Display the incoming connection.
			wafutils.WriteEventToLog(originReq, 
			{
				is_blocked: false, 
				message: 'New Connection'
			});
			// wafutils.DisplayNewConnection(req);
		}
		else{
			//Warning malicious connection.
			// req.timeHandler = new Date();
			wafutils.DisplayWarningEvent({request: req, detectResult: DetectResult});
			wafutils.RedisCache(client, {request: originReq, detectResult: DetectResult});
		}	
	}
	let startChecking = async function(client, req) {
		let checkpoint = await client.get(req.remote_ip);
		let checkpointObj = JSON.parse(checkpoint);
		if(checkpointObj) {
			if (Date.now() - checkpointObj.ddosCheckpoint.timeExist < 120000) {
				if(checkpointObj.ddosCheckpoint.counter >= 20) {
					console.log('ip blocked!');
					client.del(req.remote_ip);
					wafutils.BlockConnection({
						src: req.remote_ip, 
						description: `Block dos from ${req.remote_ip}`
					});
					wafutils.WriteEventToLog(req, 
					{
						is_blocked: true, 
						detect: 'dos', 
						message: 'IP has been blocked in iptables'
					});
					wafutils.BotTele({reason: 'Exceeded Threshhold of Number Req/s', request: req }, checkpointObj);
				}
				else {
					let checkpoint = await client.get(req.remote_ip);
					let checkpointObj = JSON.parse(checkpoint);
					checkpointObj.ddosCheckpoint.counter += 1;
					client.set(req.remote_ip, JSON.stringify(checkpointObj));
					client.expire(req.remote_ip, 120);
					console.log(checkpointObj);
				}
			}
			if (Date.now() - checkpointObj.ddosCheckpoint.timeExist >= 120000) {
				checkpointObj.ddosCheckpoint.timeExist = Date.now();
				checkpointObj.ddosCheckpoint.counter = 0;
				client.set(req.remote_ip, JSON.stringify(checkpointObj));
				client.expire(req.remote_ip, 120);
				console.log(checkpointObj);
			}
		}
		else {
			client.set(req.remote_ip, JSON.stringify({
				payloadCheckpoint: {
					total: 0,
				},
				ddosCheckpoint: {
					timeExist: Date.now(),
					counter: 1,
				},
			}));
			client.expire(req.remote_ip, 120);
		}
		WafEngine(wafObj, req);
	}
	startChecking(client, req)
}

//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

function WafCheckFlags(value, flag) {
	return ((value & flag) === flag);
}

function WafCheckAssertions(asserts) {
	let result = asserts[0];
	for (let k = 1; k < asserts.length; k++) {
		result = result || asserts[k];
	}
	return result;
}

//---------------------------------------------------------------------------

module.exports = {

	//Enums of Mini WAF
	WAF_MATCH_TYPE: WAF_MATCH_TYPE,

	//Base functions of Mini WAF
	WafMiddleware: WafMiddleware,

}
