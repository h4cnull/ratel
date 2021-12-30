use async_std::io;
use async_std::net::TcpStream;
use std::time::Duration;
use async_native_tls::Certificate;
use async_native_tls::TlsConnector;
use tokio::time::timeout;
use std::net::ToSocketAddrs;
use std::net::SocketAddr;
use std::error::Error;
use x509_parser::prelude::*;

pub static USER_AGENT:&'static str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36";

async fn async_tcp_stream(addr: SocketAddr,timeout:Duration) -> io::Result<TcpStream> {
    //println!("connectting to {}",addr);
    let stream = io::timeout(
        timeout,
        async move { TcpStream::connect(addr).await },
    )
    .await?;
    Ok(stream)
}

pub async fn get_cert(host:&str,port:u16,conn_timeout:Duration,write_timeout:Duration,read_timeout:Duration)-> Result<Option<Certificate>,Box<dyn Error>> {
    let addr = format!("{}:{}",host,port);
    let mut socket_addrs = addr.to_socket_addrs()?;
    let socket_addr = socket_addrs.next().unwrap();
    let stream = async_tcp_stream(socket_addr, conn_timeout).await?;
    let connector = TlsConnector::new();
    let connector = connector.danger_accept_invalid_certs(true);
    let stream= timeout(write_timeout+read_timeout,connector.connect(host, stream)).await??;
    let cert = if let Ok(cert) = stream.peer_certificate() {
        cert
    } else {
        None
    };
    return Ok(cert);
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