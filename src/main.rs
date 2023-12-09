mod protocol;

use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                match protocol::DNSQuery::from_bytes(&buf[0..size]) {
                    Ok(query) => {
                        let response = protocol::DNSResponse::for_request(query);
                        udp_socket
                            .send_to(&response.to_bytes(), source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("Error parsing query: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
