var Socks5Proxy = require("../../index.js");
var net = require("net");

var server = net.createServer();
server.on("connection", function(conn){
	var stream = new Socks5Proxy();
	conn.pipe(stream).pipe(conn);
});
server.listen(1080);