use std::io::{Error,ErrorKind};
use std::time::Duration;
use async_std::{io, future};
use async_std::net::TcpStream;
use async_native_tls::Certificate;
use async_native_tls::TlsConnector;
use x509_parser::prelude::*;

pub static USER_AGENT:&'static str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36";

pub fn fmt_req(host:&str,port:u16,method:&str,path_args:&str,headers:Vec<(&str,&str)>,body:Option<&str>)-> String {
    let mut headers = headers;
    let mut set_host = false;
    let mut set_ua = false;
    let mut set_conn = false;
    for h in headers.iter() {
        let h_l = h.0.to_lowercase();
        if h_l == "host" {
            set_host = true;
            continue;
        }
        if h_l == "user-agent" {
            set_ua = true;
            continue;
        }
        if h_l == "connection" {
            set_conn = true;
        }
    }
    let host_port:String;
    if !set_host {
        if port == 80 || port == 443 {
            host_port = host.to_string();
            headers.push(("Host",host_port.as_str()));
        } else {
            host_port = format!("{}:{}",host,port);
            headers.push(("Host",host_port.as_str()));
        }
    }
    if !set_ua {
        headers.push(("User-Agent",USER_AGENT));
    }
    if !set_conn {
        headers.push(("Connection","Close"));
    }
    let mut request_len = method.len() + path_args.len() + 14; //"GET /path_args?id=x HTTP/1.1\r\n\r\n"
    let body_len_str:String;
    if body.is_some() {
        let body_len = body.unwrap().len();
        body_len_str = body_len.to_string();
        headers.push(("Content-Length",body_len_str.as_str()));
        request_len += body_len;
    }
    for h in headers.iter() {
        request_len += h.0.len() + 2 + h.1.len() + 2;
    }
    let mut rst = String::with_capacity(request_len);
    rst += method;
    rst += " ";
    rst += path_args;
    rst += " HTTP/1.1\r\n";
    for h in headers.iter() {
        rst += h.0;
        rst += ": ";
        rst += h.1;
        rst += "\r\n";
    }
    rst += "\r\n";
    if body.is_some() {
        rst += body.unwrap();
    }
    //println!("req calc len {},req rst size {}, req alloc cap {},req {}",request_len,rst.len(),rst.capacity(),rst);  //////////////////
    return rst;
}

pub async fn https_with_cert(host:&str,port:u16,request:String,tcp_conn_timeout:Duration,http_timeout:Duration)-> Option<(Option<(u16,Option<String>,Vec<u8>,Vec<u8>)>,Option<Certificate>)>{
    if let Ok(stream) = io::timeout(tcp_conn_timeout,TcpStream::connect(format!("{}:{}",host,port))).await {
        if let Ok(rst) = future::timeout(http_timeout+tcp_conn_timeout, async {
            let connector = TlsConnector::new();
            let connector = connector.danger_accept_invalid_certs(true);
            if let Ok(s) = connector.connect(host, stream).await {
                    let cert =  if let Ok(cert) = s.peer_certificate() { cert } else { None };  //需要耗费时间
                    let rsp = if let Ok(r) = async_h1::connect(s, request.as_bytes()).await { Some(r) } else { None };
                    (rsp,cert)
            } else {
                (None,None)
            }
        }).await {
            if rst.0.is_some() || rst.1.is_some() {
                return Some(rst);
            }
        }
    }
    return None;
}

pub async fn http_cli(protocol:&str,host:&str,port:u16,request:String,tcp_conn_timeout:Duration,http_timeout:Duration)-> Result<(u16,Option<String>,Vec<u8>,Vec<u8>),Box<dyn std::error::Error>>{
    let stream = io::timeout(tcp_conn_timeout,TcpStream::connect(format!("{}:{}",host,port))).await?;
    if protocol == "https" {
        let rst = future::timeout(http_timeout, async {
            let connector = TlsConnector::new();
            let connector = connector.danger_accept_invalid_certs(true);
            let s = connector.connect(host, stream).await?;
            let rst = async_h1::connect(s, request.as_bytes()).await;
            rst
        }).await;
        match rst {
            Ok(rst) => {
                match rst {
                    Ok(rst) => {
                        return Ok(rst);
                    },
                    Err(e) => {
                        return Err(Box::new(Error::new(ErrorKind::Other,e)))
                    }
                }
            },
            Err(e) => {
                return Err(Box::new(Error::new(ErrorKind::Other,e)))
            }
        }
    } else if protocol == "http" {
        let rst = future::timeout(http_timeout, async_h1::connect(stream, request.as_bytes())).await;
        match rst {
            Ok(rst) => {
                match rst {
                    Ok(rst) => {
                        return Ok(rst);
                    },
                    Err(e) => {
                        return Err(Box::new(Error::new(ErrorKind::Other,e)))
                    }
                }
            },
            Err(e) => {
                return Err(Box::new(Error::new(ErrorKind::Other,e)))
            }
        }
    } else {
        return Err(Box::new(Error::new(ErrorKind::Other,"not http protocol")));
    }
}

pub async fn https_cert(host:&str,port:u16,tcp_conn_timeout:Duration,http_timeout:Duration)-> Result<Option<Certificate>,Box<dyn std::error::Error>> {
    let stream= io::timeout(tcp_conn_timeout,TcpStream::connect(format!("{}:{}",host,port))).await?;
    let tsl_stream = future::timeout(http_timeout, async {
        let connector = TlsConnector::new();
        let connector = connector.danger_accept_invalid_certs(true);
        let s = connector.connect(host, stream).await;
        s
    }).await??;
    let cert = tsl_stream.peer_certificate()?;
    return Ok(cert);
}

pub fn cert_parser(cert:async_native_tls::Certificate) -> Result<Vec<String>,Box<dyn std::error::Error>> {
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


pub fn find_last(source:&[u8],find:&[u8]) -> Option<usize> {
    let mut start = 0;
    let mut rst = None;
    while let Some(i) = find_slice(source,start,find) {
        start = i+1;
        rst = Some(i);
    }
    return rst;
}

pub fn find_slice(source:&[u8],start:usize,find:&[u8])-> Option<usize> {
    let source_len = source.len();
    let find_len = find.len();
    for i in start..source_len {
        if i+find_len <= source_len {
            if &source[i..i+find_len] == find {
                return Some(i);
            }
        }
    }
    return None;
}



#[derive(Debug)]
pub struct HttpUrl {
    url: String,
    scheme_end: usize,
    host_start:usize,
    host_end: usize,
    path_start:usize,
    path_end:usize,
    port:u16,
}

impl HttpUrl {
    pub fn new(mut url:String) -> Option<HttpUrl> {
        let mut scheme_end = 0;
        let mut host_start = 0;
        let mut host_end = 0;
        let mut path_start = 0;
        let mut path_end = 0;
        let mut port = 0;
        let url_bytes = url.as_bytes();
        if let Some(scheme_i) = find_slice(url_bytes, 0, b"://") {
            scheme_end = scheme_i;
            host_start = scheme_end+3;
            if let Some(port_i) = find_u8(url_bytes, host_start, b':') {
                //http://xxx:80
                host_end = port_i;
                if let Some(path_i) = find_u8(url_bytes, port_i, b'/') {
                    //http://xxx:80/xxx
                    path_start = path_i;
                    if let Ok(port_str) = std::str::from_utf8(&url_bytes[host_end+1..path_i]) {
                        if let Ok(p) = port_str.parse::<u16>() {
                            port = p;
                        }
                    }
                    //path_end
                    let mut end = if let Some(args_i) = find_u8(url_bytes, path_start, b'?') {
                        args_i
                    } else {
                        url_bytes.len() - 1
                    };
                    while path_start <= end {
                        if url_bytes[end] == b'/' {
                            path_end = end+1;
                            break;
                        }
                        end -= 1;
                    }
                } else {
                    //http://xxx:80
                    path_start = url.len();
                    path_end = path_start + 1;
                    if let Ok(port_str) = std::str::from_utf8(&url_bytes[host_end+1..]) {
                        if let Ok(p) = port_str.parse::<u16>() {
                            port = p;
                            url.push_str("/");
                        }
                    }
                }
            } else {
                //http://xxx
                if let Some(path_i) = find_u8(url_bytes, host_start, b'/') {
                    //http://xxx/xxx
                    host_end = path_i;
                    path_start = path_i;
                    let scheme_str = &url[..scheme_end];
                    if scheme_str == "http" {
                        port = 80;
                    } else {
                        port = 443;
                    }
                    //path_end
                    let mut end = if let Some(args_i) = find_u8(url_bytes, path_start, b'?') {
                        args_i
                    } else {
                        url_bytes.len() - 1
                    };
                    while path_start <= end {
                        if url_bytes[end] == b'/' {
                            path_end = end+1;
                            break;
                        }
                        end -= 1;
                    }
                } else {
                    //http://xxx
                    host_end = url.len();
                    path_start = host_end;
                    path_end = path_start + 1;
                    let scheme_str = &url[..scheme_end];
                    if scheme_str == "http" {
                        port = 80;
                    } else {
                        port = 443;
                    }
                    url.push_str("/");
                }
            }
        }
        if scheme_end > 0 && port > 0 && path_start >= host_end && host_end > host_start {
            return Some(
                HttpUrl {
                    url,
                    scheme_end,
                    host_start,
                    host_end,
                    path_start,
                    path_end,
                    port
                }
            );
        } else {
            return None;
        }
    }
    
    pub fn protocol(&self) ->&str {
        &self.url[..self.scheme_end]
    }

    pub fn host(&self) ->&str {
        &self.url[self.host_start..self.host_end]
    }
    // http://127.0.0.1/a/b/
    pub fn url_with_path(&self) -> &str {
        &self.url[..self.path_end]
    }
    // /a/b/
    pub fn path(&self) -> &str {
        &self.url[self.path_start..self.path_end]
    }

    // /a/b/test.php?a=1
    pub fn path_args(&self) -> &str {
        &self.url[self.path_start..]
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

pub fn find_u8(source:&[u8],start:usize,find:u8)->Option<usize> {
    for i in start..source.len() {
        if source[i] == find {
            return Some(i);
        }
    }
    return None;
}

pub fn url_parser(url_bytes:&[u8])->Option<(&str,&str,u16,&str)> {
    if let Some(proto_i) = find_slice(url_bytes, 0, b"://") {
        if let Ok(protocol) = std::str::from_utf8(&url_bytes[..proto_i]) {
            if let Some(path_args_i) = find_slice(url_bytes, proto_i+3, b"/") {
                if let Ok(path_args) = std::str::from_utf8(&url_bytes[path_args_i..]) {
                    if let Some(port_i) = find_slice(url_bytes, proto_i+3, b":") {
                        if let Ok(host) = std::str::from_utf8(&url_bytes[proto_i+3..port_i]) {
                            if let Ok(port_str) = std::str::from_utf8(&url_bytes[port_i+1..path_args_i]) {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    return Some((protocol,host,port,path_args));
                                }
                            }
                        }
                    } else {
                        if let Ok(host) = std::str::from_utf8(&url_bytes[proto_i+3..path_args_i]) {
                            if protocol == "http" {
                                return Some((protocol,host,80,path_args));
                            } else if protocol == "https" {
                                return Some((protocol,host,443,path_args));
                            } else {
                                return None;
                            }
                        }
                    }
                }
            }
        }
    }
    return None;
}