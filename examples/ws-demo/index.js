var WebSocketServer = require('ws').Server
  , http = require('http')
  , express = require('express')
  , app = express()
  , wsStream = require("./ws-stream.js")
  , Socks5Proxy = require("../../index.js");

app.use(express.static(__dirname + '/public'));

var server = http.createServer(app);
server.listen(8080);

var wss = new WebSocketServer({server: server});
wss.on('connection', function(ws) {
	var stream = new wsStream(ws);
	stream.pipe(new Socks5Proxy()).pipe(stream);
});