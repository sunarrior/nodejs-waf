const Waf = require('./wafbase');

const RegexDict = {
	XSS: {
		REGEX: {
			USING_HTML_COMMON_TAG: {
				RE: /\<\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)[^\>]*\>(.*?)\<\s*\/\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)\>/igm,
				DSC: 'XSS attack using HTML common tags.',
			},
			FUNCTION_CLASS_ARRAY_INJECTION: {
				RE: /\bFunction\s*[({](.|\s)*?[})]\s*\(.*?\)|\bfunction\s*\(.*?\)\s*{(.|\s)*?}|(?:\[|new)\s*class\s*extends\b|\bArray\s*.*\s*from\b/igm,
				DSC: 'XSS attack by function, class or array injection.'
			},
			DOM_BASE_INJECTION_1: {
				RE: /\b(?:document|window|this)\s*\[.+?\]\s*[\[(]/igm,
				DSC: 'XSS DOM based injection #1.'
			},
			DOM_BASE_INJECTION_2: {
				RE: /\bdocument\s*\.\s*(?:body|cookie|location|open|write(?:ln)?)\s*(\(|\[|\=\s*(\"|\')+)+.*(\)|\]|(\"|\')+)+/igm,
				DSC: 'XSS DOM based injection #2.'
			},
			DOM_BASE_BY_HTML_EVENT_ATTR: {
				RE: /<.+?\bon[a-z]{3,19}\b\s*=.+?>/igm,
				DSC: 'XSS DOM based by HTML event attributes.'
			},
			DOM_POISON_BASE_BY_COMMON_ATTR: {
				RE: /<.+?\b(?:href|(?:form)?action|background|code|data|location|name|poster|src|value)\s*=\s*['\"]?(?:(?:f|ht)tps?:)?\/\/\w+\.\w*/igm,
				DSC: 'XSS DOM poisoning based by common attributes.'
			},
			DEFACE_ATTACK_BY_EMBEDDED_CSS_ATTR: {
				RE: /\W(?:background(-image)?|-moz-binding)\s*:[^}]*?\burl\s*\([^)]+?(https?:)?\/\/\w/igm,
				DSC: 'XSS possible deface attack by embedded (S)CSS attributes.'
			},
			ATTACK_BY_UNESCAPED_CHAR: {
				RE: /\xBC\/script\xBE/igm,
				DSC: 'XSS attack by 0xbc, 0xbe unescaped char.'
			},
			ATTACK_BY_INVOKE_PREFIX_METHOD: {
				RE: /(\'|\"){0,1}(JAVA|VB)SCRIPT:.(\'|\"){0,1}/igm,
				DSC: 'XSS attack by invoke prefix method in request.'
			},
			ATTACK_BY_EVAL_OR_LOCAL_FUNCTION_CALL: {
				RE: /(EVAL|ALERT|CONFIRM)+(\()+(\'|\")+.*?(\'|\")+(\))+\;?/igm,
				DSC: 'XSS attack by eval or local function call.'
			},
		},
		TYPE: 'XSS',
	},
	PathTraversal: {
		REGEX: {
			PATH_TRAVERSAL_ATTACK: {
				RE: /(\.\.(\/|\\)|\.\.%(2F|5C))|(.env)+/igm,
				DSC: 'Path traversal attack.'
			},
		},
		TYPE: 'PathTraversal',
	},
	SQLi: {
		REGEX: {
			SQL_INJECTION_ATTACK: {
				RE: /(\s*([\0\b\'\"\n\r\t\%\_\\]*\s*(((select\s*.+\s*from\s*.+)|(insert\s*.+\s*into\s*.+)|(update\s*.+\s*set\s*.+)|(delete\s*.+\s*from\s*.+)|(drop\s*.+)|(truncate\s*.+)|(alter\s*.+)|(exec\s*.+)|(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+)|(let\s+.+[\=]\s*.*)|(begin\s*.*\s*end)|(\s*[\*]+\s*.*\s*[\*]+)|(\s*(\-\-)\s*.*\s+)|(\s*(contains|containsall|containskey)\s+.*)))(\s*[\;]\s*)*)+)/i,
				DSC: 'SQL injection attack.'
			},
		},
		TYPE: 'SQLInjection',
	},
	NullByte: {
		REGEX: {
			NULL_BYTE_ATTACK: {
				RE: /\x00/gm,
				DSC: 'ASCII character 0x00 (NULL BYTE) injection attack.'
			},
		},
		TYPE: 'NullByte',
	},
	FileInclusion: {
		REGEX: {
			REMOTE_FILE_INCLUSION_BY_FTP: {
				RE: /^(?:ftp):\/\/[^\/]+\/.+/i,
				DSC: 'Possible Remote File Inclusion attack by remote FTP host.'
			},
		},
		TYPE: 'RemoteFileInclusion',
	},
	UploadFile: {
		REGEX: {
			UPLOAD_FILE: {
				RE: /filename[^;\n=]*=((['"]).*?\2|[^;\n]*).(php|js)/g,
				DSC: 'Upload File Attack.'
			},
		},
		TYPE: 'UploadFile'
	},
	ExcessiveHeader: {
		REGEX: {
			EXESSIVE_HEADER_ATTACK: {
				RE: /(?:\\x[a-f0-9]{2,4}){25}/igm,
				DSC: 'Excessive hexadecimal field.'
			},
		},
		TYPE: 'ExcessiveHeader'
	},
	ScanTool: {
		REGEX: {
			SCAN_TOOL: {
				RE: /(?:analyzer|bandit|emailmagnet|ex(ploit|tract)|flood|grabber|harvest|inspect|NetLyzer|scanner|sqlmap)/igm,
				DSC: 'Known Botnet or Scan tool.'
			},
		},
		TYPE: 'ScanTool',
	},
}

const Rules = {
	MatchTypes: [
		Waf.WAF_MATCH_TYPE.MATCH_USER_AGENT |
		Waf.WAF_MATCH_TYPE.MATCH_HEADERS |
		Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING |
		Waf.WAF_MATCH_TYPE.MATCH_BODY |
		Waf.WAF_MATCH_TYPE.MATCH_FILE_EXT
	],
	MethodTypes: "GET|POST|PUT|PATCH|DELETE",
	
	UserAgents: [
		RegexDict.ScanTool,
		RegexDict.SQLi,
		RegexDict.XSS,
	],

	Headers: [
		RegexDict.XSS,
		RegexDict.PathTraversal,
		RegexDict.SQLi,
		RegexDict.NullByte,
	],

	QueryStrings: [
		RegexDict.XSS,
		RegexDict.PathTraversal,
		RegexDict.SQLi,
		RegexDict.NullByte,
		RegexDict.FileInclusion,
		RegexDict.ExcessiveHeader,
	],

	UploadFile: RegexDict.UploadFile,

	Bodys: [
		RegexDict.XSS,
		RegexDict.PathTraversal,
		RegexDict.SQLi,
	],
}

module.exports = {

	Rules: Rules

}
