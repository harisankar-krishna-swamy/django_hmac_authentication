let skip_request_name = "Obtain HMAC key";
if (pm.info.requestName === skip_request_name)
{ return; }

var api_key = pm.environment.get("api_key");
var secret = CryptoJS.enc.Base64.parse(pm.environment.get("api_secret"));
var date = new Date().toISOString();
date = date.replace("Z", "+00:00");

var body = pm.request.body;
body = (!body.raw) ? null: JSON.stringify(JSON.parse(body.raw));
var body_hash = (body != null) ? CryptoJS.enc.Base64.stringify(CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(body))): null;

var string_to_sign = ";"+date;
string_to_sign = (body_hash) ? body_hash + string_to_sign: string_to_sign;

var signature = CryptoJS.HmacSHA256(string_to_sign, secret);
signature = CryptoJS.enc.Base64.stringify(signature);

var header = "HMAC-SHA256 " + api_key + ";" + signature + ";" + date
pm.environment.set("header", header);