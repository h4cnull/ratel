use std::time::Duration;
use std::net::ToSocketAddrs;
use std::net::SocketAddr;
use std::error::Error;

use async_std::io;
use async_std::net::TcpStream;
use async_native_tls::Certificate;
use async_native_tls::TlsConnector;
use x509_parser::prelude::*;

pub static USER_AGENT:&'static str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36";

async fn async_tcp_stream(addr: &SocketAddr,timeout:Duration,retries:u8) -> Option<TcpStream> {
    for _ in 0..=retries {
        if let Ok(stream) = io::timeout(timeout,TcpStream::connect(addr)).await {
            return Some(stream);
        }
    }
    return None;
}

pub async fn get_cert(host:&str,port:u16,conn_timeout:Duration,write_timeout:Duration,read_timeout:Duration)-> Option<Certificate> {
    let addr = format!("{}:{}",host,port);
    if let Ok(mut socket_addrs) = addr.to_socket_addrs() {
        let socket_addr = socket_addrs.next().unwrap();
        if let Some(stream) = async_tcp_stream(&socket_addr, conn_timeout,1).await {
            let connector = TlsConnector::new();
            let connector = connector.danger_accept_invalid_certs(true);
            if let Ok(stream) = io::timeout(write_timeout+read_timeout,async {
                if let Ok(s) = connector.connect(host, stream).await {
                    return Ok(s);
                } else {
                    return Err(io::Error::new(io::ErrorKind::Other, ""));
                }
            }).await {
                if let Ok(cert) = stream.peer_certificate() {
                    return cert;
                }
            };
        };
    };
    return None;
}

pub fn cert_parser(cert:async_native_tls::Certificate) -> Result<Vec<String>,Box<dyn Error>> {
    let cert_der = cert.to_der()?;
    let cert = x509_parser::parse_x509_certificate(&cert_der)?;
    let sub = cert.1.tbs_certificate.subject_alternative_name();
    match sub {
        Some(s) => {
            let subs = s.1;
            let mut subnames = Vec::new();
            for s in subs.general_names.iter() {
            match s {
                GeneralName::DNSName(name) => {
                    subnames.push(name.to_string());
                },
                _ => {}
            }
            }
            Ok(subnames)
        },
        None => { Ok(vec![]) }
    }
}

/*
pub async fn http_banner_check(host:&str,port:u16,conn_timeout:Duration,write_timeout:Duration,read_timeout:Duration)-> Option<(&'static str,Option<Certificate>)> {
    let addr = format!("{}:{}",host,port);
    if let Ok(mut socket_addrs) = addr.to_socket_addrs() {
        let socket_addr = socket_addrs.next().unwrap();
        if let Some(stream) = async_tcp_stream(&socket_addr, conn_timeout,1).await {
            let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",host,USER_AGENT);
            let connector = TlsConnector::new();
            let connector = connector.danger_accept_invalid_certs(true);
            if let Ok(mut stream) = io::timeout(write_timeout+read_timeout,async {
                if let Ok(s) = connector.connect(host, stream).await {
                    return Ok(s);
                } else {
                    return Err(io::Error::new(io::ErrorKind::Other, ""));
                }
            }).await {
                let _ = io::timeout(write_timeout,stream.write_all(req.as_bytes())).await;
                let mut buf = [0;100];
                async_std::task::sleep(std::time::Duration::from_millis(500)).await;
                let _ = io::timeout(read_timeout,stream.read(&mut buf)).await;
                if buf.starts_with(b"HTTP/") {
                    let cert = stream.peer_certificate().unwrap_or_else(|_|{ None } );
                    return Some(("https",cert));
                }
            } else {
                if let Some(mut stream) = async_tcp_stream(&socket_addr, conn_timeout,1).await {
                    let _ = io::timeout(write_timeout,stream.write_all(req.as_bytes())).await;
                    let mut buf = [0;100];
                    async_std::task::sleep(std::time::Duration::from_millis(500)).await;
                    let _ = io::timeout(read_timeout,stream.read(&mut buf)).await;
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    if buf.starts_with(b"HTTP/") {
                        return Some(("http",None));
                    }
                };
            }
        };
    };
    return None;
}
 */