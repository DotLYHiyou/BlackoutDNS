const dgram = require("dgram");
const net = require("net");
const dns = require("dns");

const udpSocket = dgram.createSocket("udp4");
udpSocket.bind(2053, "127.0.0.1");

// TCP fallback for DNS-over-TCP (firewall bypass)
const tcpServer = net.createServer((socket) => {
  let chunks = [];
  socket.on("data", (data) => {
    chunks.push(data);
    // Simple: assume all data arrives at once
    const buf = Buffer.concat(chunks).slice(2); // skip length prefix
    udpSocket.emit("message", buf, {
      address: socket.remoteAddress,
      port: socket.remotePort,
      tcpSocket: socket,
    });
  });
});
tcpServer.listen(2053, "127.0.0.1", () => {
  console.log("TCP DNS server listening on 127.0.0.1:2053");
});

udpSocket.on("message", (buf, rinfo) => {
  try {
    // Parse transaction ID
    const transactionId = buf.slice(0, 2);

    // Parse question section (extract domain)
    let offset = 12;
    let labels = [];
    while (buf[offset] !== 0) {
      const len = buf[offset];
      labels.push(buf.slice(offset + 1, offset + 1 + len).toString());
      offset += len + 1;
    }
    const domain = labels.join(".");
    // ... you can now use 'domain' to resolve or forward ...

    // If you want to forward, use Google's DNS (8.8.8.8) as fallback
    dns.resolve(domain, (err, addresses) => {
      let answer = [];
      if (!err && addresses && addresses.length) {
        // Build a simple A record answer
        const ip = addresses[0].split(".").map(Number);
        answer = [
          0xc0, 0x0c, // pointer to domain name
          0x00, 0x01, // type A
          0x00, 0x01, // class IN
          0x00, 0x00, 0x00, 0x3c, // TTL 60s
          0x00, 0x04, // data length
          ...ip,
        ];
      }
      const response = Buffer.concat([
        Buffer.from([
          ...transactionId,
          0x81,
          0x80,
          0x00,
          0x01,
          answer.length ? 0x00 : 0x00,
          answer.length ? 0x01 : 0x00,
          0x00,
          0x00,
          0x00,
          0x00,
        ]),
        buf.slice(12, offset + 1), // question section
        Buffer.from(answer),
      ]);
      if (rinfo.tcpSocket) {
        // Prepend length for TCP
        const len = Buffer.alloc(2);
        len.writeUInt16BE(response.length);
        rinfo.tcpSocket.write(Buffer.concat([len, response]));
        rinfo.tcpSocket.end();
      } else {
        udpSocket.send(response, rinfo.port, rinfo.address);
      }
    });
  } catch (e) {
    console.log(`Error receiving data: ${e}`);
  }
});

udpSocket.on("error", (err) => {
  console.log(`Error: ${err}`);
});
udpSocket.on("listening", () => {
  const address = udpSocket.address();
  console.log(`Server listening ${address.address}:${address.port}`);
});
