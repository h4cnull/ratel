use std::time::Duration;
use regex::Regex;
use std::fs;

use futures::StreamExt;
use futures::stream::FuturesUnordered;

use reqwest;
use std::str::FromStr;
use reqwest::header::{HeaderMap,HeaderName,HeaderValue};

use super::https_banner::USER_AGENT;
use super::https_banner::*;
use super::result_struct::{Record,Data,RecordType::*};
use super::ResultConfig;

use serde_json::Value;

use base64;
use murmur3::murmur3_32;
use std::io::Cursor;

pub struct Detector {
    server_regex: Regex,
    icon_regex: Regex,
    icon_href_regex: Regex,
    title_regex: Regex,
    conn_timeout: Duration,
    write_timeout: Duration,
    read_timeout: Duration,
    redirect_times: u8,
    poc_limit: u16,
    disable_poc: bool,
    pocs: Vec<Value>
}

enum Rules<'a> {
    StatusCode(u16),
    Header(Vec<&'a str>),
    Body(Vec<&'a str>),
    Favicon(i32)
}

impl Detector {
    pub fn new(conf:&ResultConfig)-> Detector {
        let pocs = if conf.disable_poc {
            vec![]
        } else {
            let pocs_file = &conf.pocs_file;
            let json_str = fs::read_to_string(pocs_file).unwrap_or_else(|e|{
                println!("[!] Read POC file {} error: {:?}",pocs_file,e.kind());
                "{
                    \"pocs\":[]
                }".to_string()
            });
            let pocs_json:Value = serde_json::from_str(json_str.trim()).unwrap_or_else(|e|{
                println!("[!] Parse POC file {} error: {}",pocs_file,e);
                Value::Null
            });
            let mut pocs:Vec<Value> = Vec::new();
            if let Some(pocs_value) = pocs_json.get("pocs") {
                if let Some(pocs_values) = pocs_value.as_array() {
                    pocs = pocs_values.clone();
                } else {
                    println!("[!] Value of \"pocs\" in POC file is not a list");
                };
            } else {
                println!("[!] Not found key \"pocs\" in POC file");
            };
            println!("[-] Total pocs {}",pocs.len());
            pocs
        };
        let server_regex = Regex::new("[Ss]erver: (.*?[a-zA-Z]+.*)?\r\n").unwrap();  //有的server是打码的 无意义
        let icon_regex = Regex::new("(<(?:link|LINK).*?rel=.*?icon.*?>)").unwrap();
        let icon_href_regex = Regex::new("href=\"?(.*?)[\" >]").unwrap();
        let title_regex = Regex::new("<(?:title|TITLE)>(.*?)</(?:title|TITLE)>").unwrap();
        //let x_powered_by = Regex::new("X-Powered-By: (.*)?\r\n")?;
        return Detector {
            server_regex,
            icon_regex,
            icon_href_regex,
            title_regex,
            conn_timeout: Duration::from_millis(conf.conn_timeout),
            write_timeout: Duration::from_millis(conf.write_timeout),
            read_timeout: Duration::from_millis(conf.read_timeout),
            redirect_times: conf.redirect_times,
            poc_limit: conf.poc_limit,
            disable_poc: conf.disable_poc,
            pocs
        };
    }

    async fn http_check(&self,url:&str,retries:u8)-> Option<(u16,String,String,String)> {
        let cli = self.unverify_client();
        for _ in 0..=retries {
            let req = (&cli).get(url).header(reqwest::header::USER_AGENT, USER_AGENT).header("Connection","Close");
            if let Ok(rsp) = req.send().await {
                let status_code = rsp.status().as_u16();
                let header = self.get_raw_header(&rsp);
                let url = rsp.url().to_string();
                let body = rsp.text().await.unwrap_or_else(|_|{"".to_string()});
                return Some((status_code,header,body,url));
            }
        }
        return None;
    }

    pub async fn detect(&self,mut record:Box<dyn Record>) -> Option<Data> {
        if record.record_type() == Other {
            return None;
        }
        let cert_domains = record.cert_domains().unwrap_or_else(||{vec![]});
        let mut data = Data {   //初始化data, host/ip/port
            title: record.title().trim().to_string(),
            host: record.host().to_string(),
            ip: record.ip().to_string(),
            port: record.port(),
            protocol: record.protocol().to_string(),
            url: None,
            infos: vec![],
            status_code: 0,
            cert_domains,
            is_assets: false,
            level:0
        };
        let mut root_header_tmp = None;
        let mut root_body_tmp = None;
        let mut current_url = None;
        //先处理Active记录
        if record.record_type() == Active {
            //如果是主动扫描结果，尝试将端口视为https http协议处理
            if let Some(rst) = self.http_check(&format!("https://{}:{}",data.host,data.port), 0).await {
                data.status_code = rst.0;
                data.protocol = "https".to_string();
                root_header_tmp = Some(rst.1);
                root_body_tmp = Some(rst.2);
                current_url = Some(rst.3);
            } else if let Some(rst) = self.http_check(&format!("http://{}:{}",data.host,data.port), 0).await {
                data.status_code = rst.0;
                data.protocol = "http".to_string();
                root_header_tmp = Some(rst.1);
                root_body_tmp = Some(rst.2);
                current_url = Some(rst.3);
            } else {
                data.protocol = "unknown".to_string();
            }
        }
        //如果是https 尝试获取证书
        if &data.protocol == "https" {
            if let Ok(cert) = get_cert(&data.host,data.port,self.conn_timeout,self.write_timeout,self.read_timeout).await {
                if let Some(cert) = cert {
                    if let Ok(mut domains) = cert_parser(cert) {
                        for _ in 0..domains.len() {
                            let d = domains.pop().unwrap();
                            if !data.cert_domains.contains(&d) {
                                data.cert_domains.push(d);
                            }
                        }
                    };
                }
            }
        };
        let mut infos = Vec::new();
        let mut level = 0;
        if &data.protocol == "http" || &data.protocol == "https" {
            data.url = Some(format!("{}://{}:{}",&data.protocol,&data.host,&data.port));
            let url = (&data.url).as_ref().unwrap();
            //如果发生了重定向，url就不是根了，从重定向后的页面获取favicon地址，如果是../开头的相对地址，就需要当前url来定位favicon地址
            if record.record_type() == Passive {
                if let Some(rst) = self.http_check(url, 1).await {
                    data.status_code = rst.0;
                    root_header_tmp = Some(rst.1);
                    root_body_tmp = Some(rst.2);
                    current_url = Some(rst.3);
                };
            }
            //如果前面http请求成功了，再继续
            if root_header_tmp.is_some() && root_body_tmp.is_some() {
                let root_header = root_header_tmp.unwrap();
                let root_body = root_body_tmp.unwrap();
                if let Some(caps) = self.server_regex.captures(&root_header) {
                    if let Some(m) = caps.get(1) {
                        let ser = m.as_str();
                        let server = if ser.len() > 500 {
                            ["honeypot server? ",&ser[0..30],"..."].join("")
                        } else if ser.len() > 100 {
                            [&ser[0..30],"..."].join("")
                        } else {
                            ser.to_string()
                        };
                        infos.push(server);
                    };
                };
                if let Some(caps) = self.title_regex.captures(&root_body) {
                    if let Some(m) = caps.get(1) {
                        let new_title = m.as_str().trim();
                        if !data.title.contains(new_title){
                            data.title += new_title
                        }
                    };
                };
                let mut favicon_url = None;
                if let Some(caps) = self.icon_regex.captures(&root_body) {
                    if let Some(m) = caps.get(1) {
                        let icon_html = m.as_str();
                        //println!("favacion html {}",icon_html); //////////////////////////
                        if let Some(caps) = self.icon_href_regex.captures(icon_html) {
                            if let Some(m) = caps.get(1) {
                                let tmp = m.as_str();
                                if tmp.starts_with("http://") || tmp.starts_with("https://") {
                                    favicon_url = Some(tmp.to_string());
                                } else if tmp.starts_with("/") {
                                    favicon_url = Some(url.to_string() + tmp)
                                } else {  //否则就是../ ./ xxx/favicon.ico 这样的格式
                                    let current_url = current_url.unwrap();
                                    favicon_url = Some(current_url + "/" + tmp)
                                }
                            }
                        }
                    };
                };
                if favicon_url.is_none() {   //如果favicon url没解析出来，则使用默认地址
                    favicon_url = Some(url.to_string()+"/favicon.ico");
                };
                //计算favicon hash!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                /////println!("favicon url {:?}",favicon_url);                      //////////////
                let favicon_hash = self.favicon_hash(&favicon_url.unwrap()).await;
                /////println!("favicon hash {:?}",favicon_hash);
                //println!("root header:\n{}",root_header);          ///////////////
                //println!("root_body:\n{}",root_body);              ///////////////
                if !self.disable_poc && data.status_code > 0 {       //如果开启了poc模块，并且目标可访问
                    let mut ftrs = FuturesUnordered::new();
                    let mut pocs_iter = self.pocs.iter();
                    for _ in 0..self.poc_limit {
                        if let Some(v) = pocs_iter.next() {
                            ftrs.push(self.poc_matcher(&data,v,&root_header,&root_body,favicon_hash));
                        }
                    }
                    while let Some(rst) = ftrs.next().await {
                        if let Some(v) = pocs_iter.next() {
                            ftrs.push(self.poc_matcher(&data,v,&root_header,&root_body,favicon_hash));
                        }
                        match rst {
                            Some(r) => {
                                level = r.1;
                                let mut contain = false;
                                for s in infos.iter() {
                                    if s.contains(&r.0) {
                                        contain = true;
                                    }
                                }
                                if ! contain {
                                    infos.push(r.0);
                                }
                            },
                            None => {}
                        } 
                    }
                }
                data.level = level;
                data.infos = infos;
            }
        }
        Some(data)
    }

    fn get_raw_header(&self,rsp:&reqwest::Response)-> String {
        let mut header_string = format!("{:?} {}\r\n",rsp.version(),rsp.status());
        for h in rsp.headers() {
            header_string += h.0.as_str();
            header_string += ": ";
            if let Ok(s) = h.1.to_str() {
                header_string += s;
            }
            header_string += "\r\n";
        }
        header_string + "\r\n"
    }

    fn unverify_client(&self) -> reqwest::Client {
        let cli = reqwest::ClientBuilder::new();
        let cli1 = cli.connect_timeout(self.conn_timeout);
        let policy = if self.redirect_times > 0 {
            reqwest::redirect::Policy::limited(self.redirect_times as usize) //最多跟随重定向2次
        } else {
            //cli1 = cli1.timeout(self.conn_timeout+self.write_timeout+self.read_timeout+Duration::from_millis(1500));
            reqwest::redirect::Policy::none()         //不跟随重定向reqwest::redirect::Policy::none();  //不跟随重定向
        };
        let cli1 = cli1.redirect(policy);
        let cli1 = cli1.danger_accept_invalid_certs(true);
        let cli2 = cli1.danger_accept_invalid_hostnames(true);
        let cli3 = cli2.build().unwrap();
        cli3
    }

    async fn poc_matcher(&self,data:&Data,v:&Value,root_header:&str,root_body:&str,favicon_hash:Option<i32>) -> Option<(String,u8)> {
        let name = v.get("name");
        let level = v.get("level");
        let method = v.get("method");
        let post_data = v.get("post_data");
        let rules = v.get("rules");
        if name.is_none() || method.is_none() || rules.is_none() {
            return None;
        };
        let level = if level.is_none() {
            0
        } else {
            let tmp = level.unwrap().as_u64().unwrap_or_else(||{0});
            tmp as u8
        };
        let method = method.unwrap().as_str().unwrap_or_else(||{""});
        if method == "post" && post_data.is_none() {
            return None;
        };
        let name = name.unwrap().as_str().unwrap_or_else(||{""});
        let rules = rules.unwrap();
        let mut path = "/";
        if let Some(v) = v.get("path") {
            if let Some(p) = v.as_str() {
                path = p
            } 
        };
        let mut need_true = Vec::new();
        
        if let Some(tmp) = rules.get("status_code") {
            if let Some(status_code) = tmp.as_u64() {
                need_true.push(Rules::StatusCode(status_code as u16));
            }
        };
        
        if let Some(tmp) = rules.get("header") {
            if let Some(arr) = tmp.as_array() {
                let mut strs = vec![];
                for keyword in arr {
                    if let Some(s) = keyword.as_str() {
                        strs.push(s);
                    }
                }
                need_true.push(Rules::Header(strs));
            }
        };
        
        if let Some(tmp) = rules.get("body") {
            if let Some(arr) = tmp.as_array() {
                let mut strs = vec![];
                for keyword in arr {
                    if let Some(s) = keyword.as_str() {
                        strs.push(s);
                    }
                }
                need_true.push(Rules::Body(strs));
            }
        };
        
        if favicon_hash.is_some() {   //如果有favicon_hash，再读取poc中的favicon
            if let Some(tmp) = rules.get("favicon") {
                if let Some(hash) =  tmp.as_i64() {
                    need_true.push(Rules::Favicon(hash as i32))
                }
            }
        }
        
        if need_true.len() == 0 {
            return None;
        }

        let url = format!("{}://{}:{}",data.protocol,data.host,data.port);
        let mut status_code = 0;
        let mut match_header = root_header;
        let mut match_header_not_root = "".to_string();
        let mut match_body = root_body;
        let mut match_body_not_root = "".to_string();

        let client = self.unverify_client();
        let mut header_map = HeaderMap::default();
        header_map.insert(HeaderName::from_str("User-Agent").unwrap(), HeaderValue::from_str(USER_AGENT).unwrap());
        if let Some(headers_tmp) = v.get("headers") {
            if let Some(headers_tmp) = headers_tmp.as_object() {
                for v in headers_tmp.iter() {
                    if let Ok(h) = HeaderName::from_str(v.0) {
                        if let Some(v) = v.1.as_str() {
                            if let Ok(v) = HeaderValue::from_str(v) {
                                header_map.insert(h, v);
                            }
                        };
                    };
                }
            };
        };
        //println!("header map {:?}",header_map);
        if method == "get" && ( path == "" || path == "/" ) {
            status_code = data.status_code;
        } else {    //否则就是非“/”请求，更新status_code，match_header，match_body
            match method {
                "get" => {
                    let req = client.get(&url).headers(header_map);
                    let rsp = req.send().await;
                    if let Ok(r) = rsp {
                        status_code = r.status().as_u16();
                        match_header_not_root = self.get_raw_header(&r);
                        if let Ok(text) = r.text().await {
                            match_body_not_root = text;
                        };
                    };
                },
                "post" => {
                    let post_data = post_data.unwrap().as_str().unwrap_or_else(||{""}).to_string();
                    let req = client.post(&url).headers(header_map)
                    .body(post_data);
                    let rsp = req.send().await;
                    if let Ok(r) = rsp {
                        status_code = r.status().as_u16();
                        match_header_not_root = self.get_raw_header(&r);
                        if let Ok(text) = r.text().await {
                            match_body_not_root = text;
                        };
                    };
                },
                "head" => {
                    let req = client.head(&url).headers(header_map);
                    let rsp = req.send().await;
                    if let Ok(r) = rsp {
                        status_code = r.status().as_u16();
                        match_header_not_root = self.get_raw_header(&r);
                    };
                },
                _ => {}
            };
            match_header = &match_header_not_root;
            match_body = &match_body_not_root;
        }
        
        for k in need_true.iter() {
            match k {
                Rules::StatusCode(s) => {
                    if status_code != *s {
                        return None;
                    }
                },
                Rules::Header(h) => {
                    for keyword in h {
                        if !match_header.contains(keyword) {
                            return None;
                        }
                    }
                },
                Rules::Body(b) => {
                    for keyword in b {
                        if !match_body.contains(keyword) {
                            return None;
                        }
                    }
                },
                Rules::Favicon(f) => {   //前面是如果有favicon_hash，才会有Rules::Favicon，所以这里能直接unwrap()
                    if *f != favicon_hash.unwrap() {
                        return None;
                    }
                }
            }
        }
        return Some((name.to_string(),level));
    }
    
    async fn favicon_hash(&self,url:&str) -> Option<i32> {
        let mut favicon_hash = None;
        let cli = self.unverify_client();
        if let Ok(rsp) = cli.get(url).header(reqwest::header::USER_AGENT, USER_AGENT).send().await {
            if rsp.status() == reqwest::StatusCode::OK {
                if let Ok(favicon_bytes) = rsp.bytes().await {
                    //println!("favicon content len: {}",favicon_bytes.len());
                    let mut base64_buf = String::new();
                    base64::encode_config_buf(favicon_bytes, base64::STANDARD, &mut base64_buf);
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
            }
        };
        return favicon_hash;
    }
}