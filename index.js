var stream = require('stream');
var util = require('util');
var Duplex = stream.Duplex;
var net = require("net");

var states = {
	WAIT_HELLO: 0,
	WAIT_AUTHENTICATION: 1,
	WAIT_CONNECTION_REQUEST: 2,
	WAIT_CONNECTION_ESTABLISHING: 3,
	CONNECTED: 4,
	INVALID: 255
};

var reqTypes = {
	CONNECT: 1,
	BIND: 2,
	UDP: 3
};

var addrTypes = {
	IPV4: 1,
	DNS: 3,
	IPV6: 4
};

var errors = {
	SUCCESS: 0,
	GENERAL_ERROR: 1,
	DISALLOWED: 2,
	NET_UNREACH: 3,
	HOST_UNREACH: 4,
	CONN_REFUSED: 5,
	TTL_EXPIRED: 6,
	CMD_NOT_SUPP: 7,
	ADDR_NOT_SUPP: 8
};

var SOCKS_VERSION = 0x05;

function Socks5Proxy(options) {
  // allow use without new operator
  if (!(this instanceof Socks5Proxy)) {
    return new Socks5Proxy(options);
  }
  Duplex.call(this, options);
  this.state = states.WAIT_HELLO;
  this.authenticators = [];
  this.authMethod = 0xff;
  this.validator = null;
  this.client = null;
  this.clientDrainCb = null;
  this.readPending = false;
}
util.inherits(Socks5Proxy, Duplex);

Socks5Proxy.prototype._read = function readBytes(n) {
	if(this.client){
		var chunk = this.client.read();
	    if (chunk){
	    	this.readPending = false;
	    	this.push(chunk);
	    } else {
	    	this.readPending = true;
	    }
	}else{
		this.readPending = true;
	}
};

Socks5Proxy.prototype.addAuthentication = function(authId, authFunc){
	this.authenticators[authId] = authFunc;
};

Socks5Proxy.prototype.setDestinationValidator = function(validator){
	this.validator = validator;
};

Socks5Proxy.prototype.createConnectErrorResponse = function(err){
	this.state = states.INVALID;
	var response = new Buffer(10);
	response.fill(0);
	response.writeUInt8(SOCKS_VERSION, 0);
	response.writeUInt8(err, 1);
	response.writeUInt8(0x00, 2);
	response.writeUInt8(0x01, 3);
	this.push(response);
	this.push(null);
};

Socks5Proxy.prototype.end = function(){
	Duplex.prototype.end.call(this);
	this.state = states.INVALID;
	if(this.client){
		this.client.end();
	}
};

Socks5Proxy.prototype.createConnection = function(reqType, addr, port){
	this.client = net.connect(port, addr);
	var me = this;
	this.client.on("error", function(error){
		if(me.state === states.WAIT_CONNECTION_ESTABLISHING){
			//No easy way to tell what happened
			console.log(error, addr, port);
			me.createConnectErrorResponse(errors.NET_UNREACH);
		}
	});
	this.client.on("drain", function(){
		if(me.clientDrainCb){
			me.clientDrainCb();
			me.clientDrainCb = null;
		}
	});
	this.client.on("end", function(){
		me.push(null);
	});
	this.client.on("readable", function(){
		if(me.readPending){
			me.readPending = false;
			me.push(this.read());
		}else{
			me.read(0);
		}
	});
	this.client.on("connect", function(){
		me.state = states.CONNECTED;
		
		var subBuf;
		if(net.isIPv4(this.localAddress)){
			subBuf = new Buffer(5);
			var octets = this.localAddress.split(".");
			subBuf.writeUInt8(addrTypes.IPV4, 0);
			for(i = 0; i < octets.length; i++){
				subBuf[i + 1] = Number(octets[i]);
			}
		}else if(net.isIPv6(this.localAddress)){
			subBuf = new Buffer(17);
			subBuf.writeUInt8(addrTypes.IPV6, 0);
			console.log("local Addr is IPV6");
			throw new Error();
		}else{
			var strLen = Buffer.byteLength(this.localAddress, "utf8");
			subBuf = new Buffer(strLen + 2);
			subBuf.writeUInt8(addrTypes.DNS, 0);
			subBuf.writeUInt8(strLen, 1);
			subBuf.write(this.localAddress, 1, "utf8");
		}
		var response = new Buffer(5 + subBuf.length);
		response.writeUInt8(SOCKS_VERSION, 0);
		response.writeUInt8(errors.SUCCESS, 1);
		response.writeUInt8(0x00, 2);
		subBuf.copy(response, 3, 0);
		response.writeUInt16BE(this.localPort, 3 + subBuf.length);
		me.push(response);
	});
};

Socks5Proxy.prototype._write = function (chunk, enc, cb) {
	var i;
	if(this.state === states.WAIT_HELLO){
		//Check protocol version
		if(chunk.readUInt8(0) !== SOCKS_VERSION){
			throw new Error("This server only supports socksv5");
		}
		var authMethods = [];
		var numAuthMethods = chunk.readUInt8(1);
		for(i = 0; i < numAuthMethods; i++){
			authMethods.push(chunk.readUInt8(i + 2));
		}
		var response = new Buffer(2);
		//Protocol version
		response.writeUInt8(SOCKS_VERSION, 0);
		if(this.authenticators.length === 0){
			this.authMethod = 0;
			this.state = states.WAIT_CONNECTION_REQUEST;
		}else{
			for(i = 0; i < this.authenticators.length; i++){
				if(this.authenticators.hasOwnProperty(i) && this.authenticators[i] && authMethods.indexOf(i) !== -1){
					this.authMethod = i;
					this.state = states.WAIT_AUTHENTICATION;
					break;
				}
			}
		}

		response.writeUInt8(this.authMethod, 1);
		this.push(response);

		if(this.authMethod === 0xff){
			this.state = states.INVALID;
			this.push(null);
		}
		cb();
	}else if(this.state === states.WAIT_AUTHENTICATION){
		//TODO
		cb();
	}else if(this.state === states.WAIT_CONNECTION_REQUEST){
		if(chunk.readUInt8(0) !== SOCKS_VERSION){
			throw new Error("This server only supports socksv5");
		}
		var requestType = chunk.readUInt8(1);
		if(requestType !== reqTypes.CONNECT){
			this.createConnectErrorResponse(errors.CMD_NOT_SUPP);
			return;
		}
		var addrType = chunk.readUInt8(3);
		var addr;
		var readPos = 4;
		if(addrType === addrTypes.IPV4){
			//ipv4 address
			addr = "";
			for(i = 0; i < 4; i++){
				if(addr !== ""){
					addr += ".";
				}
				addr += chunk.readUInt8(readPos++);
			}
		}else if(addrType === addrTypes.DNS){
			//DNS address
			var addrLen = chunk.readUInt8(readPos++);
			addr = chunk.toString("utf8", readPos, readPos + addrLen);
			readPos += addrLen;
		}else if(addrType === addrTypes.IPV6){
			//ipv6 address
			this.createConnectErrorResponse(errors.ADDR_NOT_SUPP);
			return;
		}else{
			this.createConnectErrorResponse(errors.ADDR_NOT_SUPP);
			return;
		}
		var port = chunk.readUInt16BE(readPos);
		if(!this.validator){
			this.validator = function(reqType, addr, port, vcb){ process.nextTick(function(){ vcb(true); }); };
		}
		this.state = states.WAIT_CONNECTION_ESTABLISHING;
		this.validator(requestType, addr, port, function(allow){
			if(allow){
				this.createConnection(requestType, addr, port);
			}else{
				this.createConnectErrorResponse(errors.DISALLOWED);
				return;
			}
			cb();
		}.bind(this));
	}else if(this.state === states.CONNECTED){
		if(this.client.write(chunk, enc)){
			cb();
		}else{
			this.clientDrainCb = cb;
		}
	}else{
		cb();
	}
	
};

module.exports = Socks5Proxy;