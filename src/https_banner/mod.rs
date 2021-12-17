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

/*
use async_std::prelude::*;
use chrono::DurationRound;
use std::net::Shutdown;
use std::fmt::Display;

#[derive(Debug)]
pub struct MyError {
    pub msg:String
}

impl Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}",self.msg)    
    }
}

impl Error for MyError {}

pub mod socket_http {
    use super::*;

    pub struct HttpBanner {
        pub status_code: u16,
        pub header: Vec<u8>,
        pub cert: Option<Certificate>
    }

    pub fn find_slice_index(source:&[u8],find:&[u8]) -> Option<usize> {
        let source_len = source.len();
        let find_len = find.len(); 
        for i in 0..source_len {
            if i + find_len > source_len {
                return None;
            } else {
                if &source[i..i+find_len] == find {
                    return Some(i);
                }
            }
        }
        return None;
    }

    fn parse_header_banner(data:&[u8])->Result<(u16,Vec<u8>),Box<dyn Error>> {
        if Some(0) == find_slice_index(&data, b"HTTP/1.") || Some(0) == find_slice_index(&data, b"HTTP/2.") { //检查是否HTTP/1. 开头
            if let Some(rnrn_index) = find_slice_index(&data, b"\r\n\r\n") {  //检查是否有\r\n\r\n head body分隔
                //获取响应header
                let header_len = rnrn_index + b"\r\n\r\n".len();   
                let mut header = Vec::with_capacity(header_len);
                for i in 0..header_len {
                    header.push(data[i]);
                }
                //获取响应第一行
                let first_line_end = find_slice_index(&data, b"\r\n").unwrap();
                let mut first_line = Vec::with_capacity(first_line_end);
                for i in 0..first_line_end {
                    first_line.push(data[i]);
                }
                //这是正常响应第一行最小长度
                if first_line_end < b"HTTP/1.X 200 OK".len() {
                    return Err(Box::new(
                        MyError {
                            msg: "response is not http protocol".to_string()
                        }
                    ));
                };
                //获取到status_code
                let http_ver_len = b"HTTP/1.X ".len();
                let mut status_code = Vec::with_capacity(3);
                for i in http_ver_len..http_ver_len+3 {
                    status_code.push(data[i]);
                }
                let status_code = String::from_utf8_lossy(&status_code).parse::<u16>()?;
                return Ok((status_code,header))
            };
        };
        return Err(Box::new(
            MyError {
                msg: "response is not http protocol".to_string()
            }
        ));
    }

    async fn async_tcp_stream(addr: SocketAddr,timeout:Duration) -> io::Result<TcpStream> {
        //println!("connectting to {}",addr);
        let stream = io::timeout(
            timeout,
            async move { TcpStream::connect(addr).await },
        )
        .await?;
        Ok(stream)
    }

    pub async fn get_banner(url:&str,conn_timeout:Duration,write_timeout:Duration,read_timeout:Duration)-> Result<HttpBanner,Box<dyn Error>> {
        //获取url协议
        let tmp = url.split("://").collect::<Vec<&str>>();
        let protocol = tmp[0];
        if tmp.len() < 2 {
            return Err(Box::new(
                MyError {
                    msg: format!("unknown url {}",url)
                }
            ));
        }
        if protocol != "http" && protocol != "https" {
            return Err(Box::new(
                MyError {
                    msg: format!("error protocol: {}",protocol)
                }
            ));
        }
        //获取host地址和请求资源
        let url_tail = tmp[1];
        let root_index = url_tail.find("/");
        let (mut addr,res) = if root_index.is_some() {
            let root_index = root_index.unwrap();
            (url_tail[0..root_index].to_string(),&url_tail[root_index..])
        } else {
            (url_tail.to_string(),"/")
        };
        //设置默认端口
        if !addr.contains(":") {
            if protocol == "http" {
                addr.push_str(":80")
            } else {
                addr.push_str(":443")
            }
        }
        //请求头
        let req_header = format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnetion: Close\r\n\r\n",res,addr,USER_AGENT);
        let req_header = req_header.as_bytes();
        //建立tcp连接
        let mut socket_addrs = addr.to_socket_addrs()?;
        let socket_addr = socket_addrs.next().unwrap();
        let mut stream = async_tcp_stream(socket_addr, conn_timeout).await?;
        if protocol == "http" {   //处理http请求
            //发送超时3s
            io::timeout(write_timeout, async { stream.write_all(req_header).await }).await?;
            let mut data = vec![];
            io::timeout(read_timeout,async { stream.read_to_end(&mut data).await }).await.unwrap_or_else(|_|{0});
            let (status_code,header) = parse_header_banner(&data)?;
            stream.shutdown(Shutdown::Both).unwrap_or_else(|_|{});
            return Ok(HttpBanner {
                    status_code,
                    header,
                    cert: None
                }
            );
        } else {  //处理https请求
            //关闭ssl证书验证
            let connector = TlsConnector::new();
            let connector = connector.danger_accept_invalid_certs(true);
            //获取host
            let host = addr.split(":").collect::<Vec<&str>>()[0];
            let stream= timeout(write_timeout+read_timeout,connector.connect(host, stream)).await?;
            let mut stream = stream?;
            io::timeout(write_timeout,async { stream.write_all(&req_header).await }).await?;
            let mut data = vec![];
            io::timeout(read_timeout,async { stream.read_to_end(&mut data).await }).await.unwrap_or_else(|_|{0});
            let (status_code,header) = parse_header_banner(&data)?;
            let cert = if let Ok(cert) = stream.peer_certificate() {
                cert
            } else {
                None
            };
            return Ok(HttpBanner {
                    status_code,
                    header,
                    cert
                }
            );
        }
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
}
*/