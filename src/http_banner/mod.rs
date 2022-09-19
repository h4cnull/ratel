use std::collections::HashMap;
use std::error::Error;
use tokio::time::Duration;
use tokio::time::timeout;
use tokio_native_tls::native_tls::{TlsConnector,Certificate};
use tokio::net::TcpStream;
use tokio::io::BufReader;
use tokio::io::{AsyncBufReadExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use http_types::{ensure, format_err};
use async_chunked_transfer::Decoder;
use murmur3::murmur3_32;
use x509_parser::prelude::*;
use std::io::Cursor;

pub static USER_AGENT:&'static str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36";

/// The maximum amount of headers parsed on the server.
const MAX_HEADERS: usize = 128;

/// The maximum length of the head section we'll try to parse.
/// See: https://nodejs.org/en/blog/vulnerability/november-2018-security-releases/#denial-of-service-with-large-http-headers-cve-2018-12121
const MAX_HEAD_LENGTH: usize = 6 * 1024;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const ZERO: u8 = b'0';

pub enum HTTPMethod {
    GET,
    POST,
    HEAD,
    OPTIONS,
    PUT,
    DELETE,
    TRACE,
    PATCH
}

impl HTTPMethod {
    pub fn as_str(&self) -> &'static str {
        match &self {
            HTTPMethod::GET => {"GET"},
            HTTPMethod::POST => {"POST"},
            HTTPMethod::HEAD => {"HEAD"},
            HTTPMethod::OPTIONS => {"OPTIONS"},
            HTTPMethod::PUT => {"PUT"},
            HTTPMethod::DELETE => {"DELETE"},
            HTTPMethod::TRACE => {"TRACE"},
            HTTPMethod::PATCH => {"PATCH"},
        }
    }
}

#[derive(Debug,Clone)]
pub struct HttpClient {
    conn_timeout:Duration,
    read_timeout:Duration,
    http_timeout:Duration,
}

impl HttpClient {
    pub fn default()-> Self {
        HttpClient { 
            conn_timeout: Duration::from_secs(3), 
            read_timeout: Duration::from_secs(1), 
            http_timeout: Duration::from_secs(15)
        }
    }
    pub fn set_conn_timeout(&mut self,timeout:Duration) {
        self.conn_timeout = timeout;
    }
    pub fn set_read_timeout(&mut self,timeout:Duration) {
        self.read_timeout = timeout;
    }
    pub fn set_http_timeout(&mut self,timeout: Duration) {
        self.http_timeout = timeout;
    }
    pub fn get(&self,url:String) -> Result<RawRequest,&'static str> {
        match HttpUrl::new(url) {
            Ok(url) => {
                let mut headers = HashMap::new();
                headers.insert("User-Agent", USER_AGENT);
                headers.insert("Connection", "Close");
                Ok(RawRequest{
                    method:"GET",
                    url,
                    headers,
                    user_set_headers_host:false,
                    body:None,
                    cli:&self
                })
            },
            Err(e) => {
                Err(e)
            }
        }
    }
    pub fn request<'a>(&'a self,methord:HTTPMethod,url:String,body:Option<&'a str>) -> Result<RawRequest<'a>,&'static str> {
        match HttpUrl::new(url) {
            Ok(url) => {
                let mut headers = HashMap::new();
                headers.insert("User-Agent", USER_AGENT);
                headers.insert("Connection", "Close");
                Ok(RawRequest{
                    method:methord.as_str(),
                    url,
                    headers,
                    user_set_headers_host:false,
                    body,
                    cli:&self
                })
            },
            Err(e) => {
                Err(e)
            }
        }
    }

}

pub struct RawRequest<'a> {
    method:&'static str,
    pub url:HttpUrl,
    headers:HashMap<&'a str,&'a str>,
    user_set_headers_host:bool,
    body:Option<&'a str>,
    cli:&'a HttpClient,
}

impl<'a> RawRequest<'a> {
    pub fn set_headers(&mut self,headers: Vec<(&'a str, &'a str)>)->&mut Self {
        for (k,v) in headers {
            let key = k.to_lowercase();
            if key == "host" {
                self.user_set_headers_host = true;
            }
            if key == "user-agent" {
                self.headers.remove("User-Agent");
                self.headers.insert(k, v);
                continue;
            }
            if key == "connection" {
                self.headers.remove("Connection");
                self.headers.insert(k, v);
                continue;
            }
            if key == "content-length" {
                self.headers.remove("Content-Length");
                self.headers.insert(k, v);
                continue;
            }
            self.headers.insert(k, v);
        }
        self
    }

    pub async fn send(&self)->Result<RawResponse, Box<dyn Error>> {
        let addr = format!("{}:{}", self.url.host(), self.url.port());
        let stream = timeout(self.cli.conn_timeout, TcpStream::connect(&addr)).await??;    
        let raw_req = self.fmt_req();
        if self.url.is_https {
            let mut native_tls_connector = TlsConnector::builder();
            native_tls_connector.danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true);
            let tls_connector = tokio_native_tls::TlsConnector::from(native_tls_connector.build()?);
            let mut stream = timeout(self.cli.conn_timeout, tls_connector.connect(self.url.host(), stream)).await??;
            let mut cert = None;
            let tls_stream_allow = stream.get_mut();
            if let Ok(cert_) = tls_stream_allow.peer_certificate() {
                cert = cert_;
            };
            let rst = timeout(self.cli.http_timeout, self.write_and_read(stream, raw_req.as_bytes())).await?;
            let rst = rst?;
            Ok(RawResponse{
                status_code:rst.0,
                location:rst.1,
                raw_header:rst.2,
                raw_body:rst.3,
                cert
            })
        } else {
            let rst = timeout(self.cli.http_timeout, self.write_and_read(stream, raw_req.as_bytes())).await?;
            let rst = rst?;
            Ok(RawResponse{
                status_code:rst.0,
                location:rst.1,
                raw_header:rst.2,
                raw_body:rst.3,
                cert:None
            })
        }
    }
    
    pub async fn send_req(&self,raw_req:String)->Result<RawResponse, Box<dyn Error>> {
        let addr = format!("{}:{}", self.url.host(), self.url.port());
        let stream = timeout(self.cli.conn_timeout, TcpStream::connect(&addr)).await??;    
        if self.url.is_https {
            let mut native_tls_connector = TlsConnector::builder();
            native_tls_connector.danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true);
            let tls_connector = tokio_native_tls::TlsConnector::from(native_tls_connector.build()?);
            let mut stream = timeout(self.cli.conn_timeout, tls_connector.connect(self.url.host(), stream)).await??;
            let mut cert = None;
            let tls_stream_allow = stream.get_mut();
            if let Ok(cert_) = tls_stream_allow.peer_certificate() {
                cert = cert_;
            };
            let rst = timeout(self.cli.http_timeout, self.write_and_read(stream, raw_req.as_bytes())).await?;
            let rst = rst?;
            Ok(RawResponse{
                status_code:rst.0,
                location:rst.1,
                raw_header:rst.2,
                raw_body:rst.3,
                cert
            })
        } else {
            let rst = timeout(self.cli.http_timeout, self.write_and_read(stream, raw_req.as_bytes())).await?;
            let rst = rst?;
            Ok(RawResponse{
                status_code:rst.0,
                location:rst.1,
                raw_header:rst.2,
                raw_body:rst.3,
                cert:None
            })
        }
    }

    async fn write_and_read<RW>(&self,mut stream: RW, raw_request: &[u8]) -> http_types::Result<(u16,Option<String>,Vec<u8>,Vec<u8>)>
    where
        RW: AsyncReadExt + AsyncWriteExt + Send + Sync + Unpin + 'static,
    {
        let _ = stream.write_all(raw_request).await;
        let mut reader = BufReader::new(stream);
        let mut raw_header = Vec::new();
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut httparse_res = httparse::Response::new(&mut headers);
        // Keep reading bytes from the stream until we hit the end of the stream.
        loop {
            let bytes_read = timeout(self.cli.read_timeout, reader.read_until   (LF, &mut raw_header)).await;
            if bytes_read.is_err() {
                return Err(format_err!("read http header timeout"));
            }
            let bytes_read = bytes_read.unwrap();
            if bytes_read.is_err() {
                return Err(format_err!("read http header error"));
            }
            let bytes_read = bytes_read.unwrap();
            // No more bytes are yielded from the stream.
            match (bytes_read, raw_header.len()) {
                (0, 0) => return Err(format_err!("connection closed")),
                (0, _) => return Err(format_err!("empty response")),
                _ => {}
            }
            // Prevent CWE-400 DDOS with large HTTP Headers.
            ensure!(
                raw_header.len() < MAX_HEAD_LENGTH,
                "Head byte length should be less than 8kb"
            );
            // We've hit the end delimiter of the stream.
            let idx = raw_header.len() - 1;
            if idx >= 3 && raw_header[idx - 3..=idx] == [CR, LF, CR, LF] {
                break;
            }
            //if idx >= 1 && raw_header[idx - 1..=idx] == [LF, LF] {
            //    break;
            //}
        }

        // Convert our header buf into an httparse instance, and validate.
        let status = httparse_res.parse(&raw_header)?;
        ensure!(!status.is_partial(), "Malformed HTTP head");
        let code = httparse_res.code;
        let code = code.ok_or_else(|| format_err!("No status code found"))?;

        let mut location = None;
        let mut content_length = None;
        let mut chunked_encoding = false;

        let mut headers_map = Vec::new();
        for header in httparse_res.headers.iter() {
            let name = header.name.to_lowercase();
            let v = std::str::from_utf8(header.value)?;
            if name == "content-length" {
                content_length = Some(v);
            }
            headers_map.push((name,v));
        }

        for header in headers_map.iter() {
            if header.0 == "location" {
                location = Some(header.1.to_string());
                break;
            }
        }

        if content_length.is_none() {
            for header in headers_map.iter() {
                if header.0 == "transfer-encoding" {
                    if header.1 == "chunked" {
                        chunked_encoding = true;
                        break;
                    }
                }
            }
        }

        //let content_length = httparse_res.headers. .header(CONTENT_LENGTH);
        // Check for Content-Length.
        let body = if let Some(len) = content_length {
            let len = len.parse::<usize>()?;
            let mut body = Vec::with_capacity(len);
            let mut total = 0;
            loop {
                let mut buf = [0;1024];
                let bytes_read = timeout(self.cli.read_timeout, reader.read(&mut buf)).await;
                if bytes_read.is_err() {
                    break;
                }
                let bytes_read = bytes_read.unwrap();
                if bytes_read.is_err() {
                    break;
                }
                let bytes_read = bytes_read.unwrap();
                //let bytes_read = reader.read_until(LF, &mut body).await?;
                match (bytes_read, body.len()) {
                    (0, 0) => break,
                    (0, _) => break,
                    _ => {
                        for i in 0..bytes_read {
                            body.push(buf[i]);
                        }
                        total += bytes_read;
                        if total >= len {
                            break;
                        }
                    }
                }
            }
            body
        } else {
            if chunked_encoding {
                let mut chunked_body = vec![];
                loop {
                    let bytes_read = timeout(self.cli.read_timeout, reader. read_until(LF, &mut chunked_body)).await;
                    if bytes_read.is_err() {
                        break;
                    }
                    let bytes_read = bytes_read.unwrap();
                    if bytes_read.is_err() {
                        break;
                    }
                    let bytes_read = bytes_read.unwrap();
                    // No more bytes are yielded from the stream.
                    match (bytes_read, chunked_body.len()) {
                        (0, 0) => break,
                        (0, _) => break,
                        _ => {}
                    }
                    // We've hit the end delimiter of the stream.
                    let idx = chunked_body.len() - 1;
                    if idx >= 6 && chunked_body[idx - 6..=idx] == [CR, LF, ZERO, CR, LF, CR, LF] {
                        break;
                    }
                }
                let mut decoder = Decoder::new(chunked_body.as_slice());
                let mut output = vec![];
                if decoder.read_to_end(&mut output).await.is_ok() {
                    output
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };
        Ok((code,location,raw_header,body))
    }

    pub fn fmt_req(&self) -> String {
        let mut headers = self.headers.clone();
        let mut host_port = None;
        if !self.user_set_headers_host {  
            if !(self.url.port() == 80 || self.url.port() == 443) {
                host_port = Some(format!("{}:{}",self.url.host(),self.url.port()));
            }
            if host_port.is_some() {
                headers.insert("Host", host_port.as_ref().unwrap().as_str());
            } else {
                headers.insert("Host", self.url.host());
            }
        }
        let mut request_len = self.method.len() + self.url.path_args().len() + 14; //"GET /path_args?id=x HTTP/1.1\r\n\r\n"
        let body_len_str:String;
        if self.body.is_some() {
            let body_len = self.body.unwrap().len();
            request_len += body_len;
            body_len_str = body_len.to_string();
            headers.insert("Content-Length", body_len_str.as_str());
        }
        for h in headers.iter() {
            request_len += h.0.len() + 2 + h.1.len() + 2;
        }
        let mut rst = String::with_capacity(request_len);
        rst += self.method;
        rst += " ";
        rst += self.url.path_args();
        rst += " HTTP/1.1\r\n";
        for h in headers.iter() {
            rst += h.0;
            rst += ": ";
            rst += h.1;
            rst += "\r\n";
        }
        rst += "\r\n";
        if self.body.is_some() {
            rst += self.body.unwrap();
        }
        //log::info!("{}",rst);
        //println!("req calc len {},req rst size {}, req alloc cap {},req {}",request_len,rst.len(),rst.capacity(),rst);  //////////////////
        return rst;
    }
}

pub struct RawResponse {
    pub status_code:u16,
    pub location:Option<String>,
    pub raw_header:Vec<u8>,
    pub raw_body:Vec<u8>,
    pub cert:Option<Certificate>
}

pub async fn http_favicon_hash(url:String,http_timeout:Duration) -> Option<i32> {
    let mut cli = HttpClient::default();
    cli.set_http_timeout(http_timeout);
    let mut favicon_hash = None;
    //if let Ok(rsp) = http_cli(url.protocol(), host,port, req, self.http_conn_timeout, self.http_timeout).await {
    let req = cli.get(url).unwrap();
    if let Ok(rsp) = req.send().await {
        if rsp.status_code == 200 {
            let mut base64_buf = String::new();
            base64::encode_config_buf(rsp.raw_body, base64::STANDARD, &mut base64_buf);
            let base64_buf = base64_buf.as_bytes();
            //给base64按照标准加上'\n' 标准参考python的base64.encodebytes()
            let mut base64_buf_pad_n = vec![];
            for i in 0..base64_buf.len() {
                if i !=0 && i % 76 == 0{
                    base64_buf_pad_n.push(b'\n');
                }
                base64_buf_pad_n.push(base64_buf[i]);
            }
            if Some(&b'\n') != base64_buf_pad_n.last() {  //最后一个元素加上\n
                base64_buf_pad_n.push(b'\n');
            }
            //println!("base64 favicon bytes len: {}",base64_buf_pad_n.len());
            let mut cur = Cursor::new(&base64_buf_pad_n);
            favicon_hash = Some(murmur3_32(&mut cur, 0).unwrap() as i32);
        }
    };
    return favicon_hash;
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

pub fn find_u8(source:&[u8],start:usize,find:u8)->Option<usize> {
    for i in start..source.len() {
        if source[i] == find {
            return Some(i);
        }
    }
    return None;
}

#[derive(Debug)]
pub struct HttpUrl {
    url: String,
    is_https: bool,
    scheme_end: usize,
    host_start:usize,
    host_end: usize,
    path_start:usize,
    path_end:usize,
    port:u16,
}

impl HttpUrl {
    pub fn new(mut url:String) -> Result<HttpUrl,&'static str> {
        let mut scheme_end = 0;
        let mut host_start = 0;
        let mut host_end = 0;
        let mut path_start = 0;
        let mut path_end = 0;
        let mut port = 0;
        let url_bytes = url.as_bytes();
        let mut is_https = false;
        if let Some(scheme_i) = find_slice(url_bytes, 0, b"://") {
            scheme_end = scheme_i;
            if &url[..scheme_end] == "http" || &url[..scheme_end] == "https" {
                if scheme_end == 5 {
                    is_https = true;
                }
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
            } else {
                return Err("not http url");
            }
            
        }
        if scheme_end > 0 && port > 0 && path_start >= host_end && host_end > host_start {
            return Ok(
                HttpUrl {
                    url,
                    scheme_end,
                    host_start,
                    host_end,
                    path_start,
                    path_end,
                    port,
                    is_https
                }
            );
        } else {
            return Err("url format error");
        }
    }
    
    pub fn scheme(&self) ->&str {
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

    pub fn as_str(&self) -> &str {
        &self.url
    }
}

pub fn cert_parser(cert:Certificate) -> Result<Vec<String>,Box<dyn std::error::Error>> {
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