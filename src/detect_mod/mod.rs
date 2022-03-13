use std::collections::HashMap;
use std::time::Duration;
use std::io::Cursor;
use regex::{Regex,RegexBuilder};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use base64;
use murmur3::murmur3_32;
use serde::Deserialize;
use super::RecordType;
use super::http_banner::*;
use super::result_struct::{Record,Data,RecordType::*};
use super::ResultConfig;

pub struct Detector {
    server_regex: Regex,
    icon_regex: Regex,
    icon_href_regex: Regex,
    title_regex: Regex,
    conn_timeout: Duration,
    http_timeout: Duration,
    follow_redirect: bool,
    per_url_limit: u16,
    disable_poc: bool,
    pocs: Vec<Poc>,
    favicon_hash_in_pocs: bool
}

#[derive(Debug,Deserialize)]
pub struct Pocs {
    pub pocs:Vec<Poc>,
}

#[derive(Debug,Deserialize)]
pub struct Poc {
    pub name:String,
    pub level:Option<u8>,  //defalut 1
    pub requests:Vec<PocRequest> 
}

#[derive(Debug,Deserialize)]
pub struct PocRequest {
    pub path_args:Option<String>,
    pub method:Option<String>,
    pub headers:Option<HashMap<String,String>>,
    pub req_body:Option<String>,
    pub variables_regex:Option<String>,
    pub regex_dot_all:Option<bool>,   //default false
    pub variables_group:Option<Vec<(String,usize)>>,
    pub rules:Option<PocRules>
}

#[derive(Debug,Deserialize)]
pub struct PocRules {
    pub status_code:Option<u16>,
    pub header:Option<Vec<String>>,
    pub body:Option<Vec<String>>,
    pub favicon:Option<i32>,
}

#[derive(Debug)]
enum Rules<'a> {
    StatusCode(u16),
    Header(&'a Vec<String>),
    Body(&'a Vec<String>),
    Favicon(i32)
}

static MAX_REDIRECT_NUM:usize = 5;

impl Detector {
    pub fn new(conf:&ResultConfig,pocs:Vec<Poc>)-> Detector {
        let mut favicon_hash_in_pocs = false;
        for p in pocs.iter() {
            for r in p.requests.iter() {
                if r.rules.is_some() {
                    if r.rules.as_ref().unwrap().favicon.is_some() {
                        favicon_hash_in_pocs = true;
                    }
                }
            }
            if favicon_hash_in_pocs {
                break;
            }
        }
        //println!("{:?}",pocs); ///////////////////////////////
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
            http_timeout: Duration::from_secs(conf.http_timeout),
            follow_redirect: conf.follow_redirect,
            per_url_limit: conf.per_url_limit,
            disable_poc: conf.disable_poc,
            pocs,
            favicon_hash_in_pocs
        };
    }

    async fn http_init(&self,protocol:&str,host:&str,port:u16)-> (u16,Vec<u8>,Vec<u8>,HttpUrl) {
        
        let mut code = 0;
        let mut raw_header = Vec::new();
        let mut body = Vec::new();
        
        let mut current_url = HttpUrl::new(format!("{}://{}:{}/",protocol,host,port)).unwrap();
        let mut next_url:Option<HttpUrl> = None;
        
        for _ in 0..MAX_REDIRECT_NUM {
            let req = if next_url.is_some() {
                let n_url = next_url.as_ref().unwrap();
                let tmp_host = n_url.host();
                let tmp_port = n_url.port();
                let tmp_path = n_url.path_args();
                fmt_req(&tmp_host, tmp_port, "GET", &tmp_path,Vec::new(),None)
            } else {
                fmt_req(host, port, "GET", "/",Vec::new(),None)
            };
            //println!("current url {:?},next_url {:?}",current_url,next_url);   ///////////
            if let Ok(rst) = http_cli(protocol, host, port, req,self.conn_timeout, self.http_timeout).await {
                if next_url.is_some() {
                    current_url = next_url.take().unwrap();
                };
                code = rst.0;
                raw_header = rst.2;
                body = rst.3;
                //println!("{}",String::from_utf8_lossy(&body));
                if self.follow_redirect && (300..400).contains(&rst.0) {
                    if let Some(u) = rst.1 {
                        if u.starts_with("/") {
                            next_url = Some(HttpUrl::new(format!("{}://{}:{}{}",current_url.protocol(),current_url.host(),current_url.port(),u)).unwrap());
                        } else if u.starts_with("http:") || u.starts_with("https") {
                            if let Some(u) = HttpUrl::new(u) {
                                next_url = Some(u);
                            } else {
                                break;
                            }
                        } else {
                            next_url = Some(HttpUrl::new(format!("{}{}",current_url.url_with_path(),u)).unwrap());
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        return (code,raw_header,body,current_url);  //end with /
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
            favicon: None,
            level:0
        };
        let mut root_header_cache = Vec::new();
        let mut root_body_cache = Vec::new();
        let mut current_url_path = None;

        //先处理Active记录
        //let root_req = fmt_req(&data.host,data.port,"GET", "/", Vec::new(), None);
        if record.record_type() == RecordType::Active {
            //如果是主动扫描结果，尝试将端口视为https http协议处理
            if data.port == 80 || data.port != 443 {
                let (code,header,body,url) = self.http_init("http", &data.host, data.port).await; 
                if code > 0 {
                    data.protocol = "http".to_string();
                    data.url = Some(format!("http://{}:{}",data.host,data.port));
                    data.status_code = code;
                    root_header_cache = header;
                    root_body_cache = body;
                    current_url_path = Some(url);
                } else if data.port == 80 {
                    data.protocol = "http".to_string();
                    data.url = Some(format!("http://{}:{}",data.host,data.port));
                }
            }
            if data.port != 80 && data.protocol == "" {
                let (code,header,body,url) = self.http_init("https", &data.host, data.port).await; 
                if code > 0 {
                    data.protocol = "https".to_string();
                    data.url = Some(format!("https://{}:{}",data.host,data.port));
                    data.status_code = code;
                    root_header_cache = header;
                    root_body_cache = body;
                    current_url_path = Some(url);
                } else if data.port == 443 {
                    data.protocol = "https".to_string();
                    data.url = Some(format!("https://{}:{}",data.host,data.port));
                }
            } 
        } else {
            if data.protocol == "http" || data.protocol == "https" {
                data.url = Some(format!("{}://{}:{}",data.protocol,data.host,data.port));
                let (code,header,body,url) = self.http_init(&data.protocol, &data.host, data.port).await;
                if code > 0 {
                    data.status_code = code;
                    root_header_cache = header;
                    root_body_cache = body;
                    current_url_path = Some(url);
                }
            }
        }
        
        let mut infos = Vec::new();
        let mut level = 0;
        if data.status_code > 0 {
            if data.protocol == "https" {
                if let Ok(cert) = https_cert(&data.host, data.port, self.conn_timeout, self.http_timeout).await {
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
            }
            //println!("{:?}",current_url_path);
            //如果发生了重定向，url就不是根了，从重定向后的页面获取favicon地址，如果是../开头的相对地址，就需要当前url来定位favicon地址
            //如果前面http请求成功了，再继续
            let root_header_tmp = String::from_utf8_lossy(&root_header_cache);
            let root_body_tmp = String::from_utf8_lossy(&root_body_cache);
            let root_url = data.url.as_ref().unwrap();
            let root_header = root_header_tmp.as_ref();
            let root_body = root_body_tmp.as_ref();
            //println!("{}",root_header);   /////////////////
            //println!("{}",root_body);     /////////////////
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
            if !self.disable_poc { //如果开启了poc模块
                let mut favicon_hash = None;
                /*
                    favicon hash 的代码逻辑。favicon_hash 是提取首页中的favicon链接计算。不会为每个不同的poc http请求结果提取计算。
                    所以，无论poc是怎样的，只要匹配favicon，那匹配的就是首页提取的favico hash，不支持指定favicon地址匹配。如：
                    {
		                "name":"xxx",
		                "path":"/xxx/xxx/favicon",
                        "rules":{
			                "favicon": 1013918534
		                }
	                }
                    这样的poc是无效的。
                */
                //println!("{}",root_body);///////////////////////////////
                if self.favicon_hash_in_pocs {
                    let mut favicon_url = None;
                    if let Some(caps) = self.icon_regex.captures(&root_body) {
                        //println!("icon caped"); ///////////////////////////////
                        if let Some(m) = caps.get(1) {
                            let icon_html = m.as_str();
                            //println!("favicon html {}",icon_html); //////////////////////////
                            if let Some(caps) = self.icon_href_regex.captures(icon_html) {
                                if let Some(m) = caps.get(1) {
                                    let tmp = m.as_str();
                                    if tmp.starts_with("http://") || tmp.starts_with("https://") {
                                        favicon_url = Some(tmp.to_string());
                                    } else if tmp.starts_with("/") {
                                        favicon_url = Some(root_url.to_string() + tmp)
                                    } else {  //否则就是../ ./ xxx/favicon.ico 这样的格式
                                        let current_url = current_url_path.unwrap();
                                        favicon_url = Some(format!("{}{}",current_url.url_with_path(),tmp));
                                    }
                                }
                            }
                        };
                    };
                    if favicon_url.is_none() {   //如果favicon url没解析出来，则使用默认地址
                        favicon_url = Some(root_url.to_string()+"/favicon.ico");
                    } else {
                        if favicon_url.as_ref().unwrap().ends_with(".svg") {
                            favicon_url = None;
                        }
                    };
                    //计算favicon hash!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    /////println!("favicon url {:?}",favicon_url);
                    if favicon_url.is_some() {
                        favicon_hash = self.favicon_hash(favicon_url.unwrap()).await;
                        data.favicon = favicon_hash;
                    }
                }
                let mut ftrs = FuturesUnordered::new();
                let mut pocs_iter = self.pocs.iter();
                for _ in 0..self.per_url_limit {
                    if let Some(p) = pocs_iter.next() {
                        ftrs.push(self.poc(&data.protocol,&data.host,data.port,p,data.status_code,&root_header,&root_body,favicon_hash));
                    }
                }
                while let Some(rst) = ftrs.next().await {
                    if let Some(p) = pocs_iter.next() {
                        ftrs.push(self.poc(&data.protocol,&data.host,data.port,p,data.status_code,&root_header,&root_body,favicon_hash));
                    }
                    match rst {
                        Some(r) => {
                            if level < r.1 {
                                level = r.1;
                            }
                            if !infos.contains(&r.0) {
                                infos.push(r.0);
                            }
                        },
                        None => {}
                    } 
                }
                data.level = level;
                data.infos = infos;
            }
        }
        Some(data)
    }

    async fn poc(&self,protocol:&str,host:&str,port:u16,poc:&Poc,root_status_code:u16,root_header:&str,root_body:&str,favicon_hash:Option<i32>) -> Option<(String,u8)> {
        let mut replace_v = None;
        for poc_req in poc.requests.iter() {
            let return_data = poc_req.variables_regex.is_some() && poc_req.variables_group.is_some();
            //println!("need return data {}",return_data); ///////////////////////
            if let Some(data) = self.poc_request(protocol,host,port,poc_req, root_status_code, root_header, root_body, favicon_hash,&replace_v,return_data).await {
                //println!("return data {:?}",data);       /////////////////////////////////////////////
                if let Some(data) = data {  //return_data is true
                    let mut tmp = HashMap::new();
                    let regex_str = poc_req.variables_regex.as_ref().unwrap();
                    let dot_all = poc_req.regex_dot_all.unwrap_or(false);   //default false
                    let mut regex_builder = RegexBuilder::new(regex_str);
                    regex_builder.dot_matches_new_line(dot_all);
                    if let Ok(vreg) = regex_builder.build() {    //如果正则表达式是正确的
                        if let Some(caps) = vreg.captures(&data) {   //如果匹配正则
                            let variables_groups = poc_req.variables_group.as_ref().unwrap();
                            for (vname,index) in variables_groups {
                                if let Some(rst) = caps.get(*index) {                     //如果在正则位置匹配到了内容
                                    tmp.insert(vname.as_str(), rst.as_str().to_string());  //将变量名称和匹配到的内容存放在hashmap。
                                }
                            }
                        }
                    };
                    /* 
                    if tmp.is_empty() {
                        replace_v = None;
                    } else {
                        replace_v = Some(tmp);
                    }*/
                    if replace_v.is_none() {
                        replace_v = Some(tmp);
                    } else {
                        let mut_ref = replace_v.as_mut().unwrap();
                        for (k,v) in tmp {
                            mut_ref.insert(k, v);
                        }
                    }
                };
            } else {
                return None;
            }
        }
        let name = poc.name.clone();
        let level = poc.level.unwrap_or(1);
        return Some((name.to_string(),level));
    }
    
    async fn poc_request(&self,protocol:&str,host:&str,port:u16,poc_req:&PocRequest,root_status_code:u16,root_header:&str,root_body:&str,favicon_hash:Option<i32>,replace_variables:&Option<HashMap<&str,String>>,return_data:bool) -> Option<Option<String>> {
        let mut need_true = Vec::new();
        if poc_req.rules.is_some() {
            let rules = poc_req.rules.as_ref().unwrap();
            if let Some(status_code) = rules.status_code {
                need_true.push(Rules::StatusCode(status_code));
            };
            if let Some(keywords) = rules.header.as_ref() {
                need_true.push(Rules::Header(keywords));
            };
            if let Some(keywords) = rules.body.as_ref() {
                need_true.push(Rules::Body(keywords));
            };
            if let Some(hash) = rules.favicon {
                need_true.push(Rules::Favicon(hash))
            }
        }
        let init_cow = Vec::new();
        let mut status_code = 0;
        let mut match_header = root_header;
        let match_header_not_root_cache:Vec<u8>;
        let mut match_header_not_root = String::from_utf8_lossy(&init_cow);
        let mut match_body = root_body;
        let match_body_not_root_cache:Vec<u8>;
        let mut match_body_not_root = String::from_utf8_lossy(&init_cow);
        let mut headers = Vec::new();
        let mut set_headers = false;
        if let Some(headers_tmp) = poc_req.headers.as_ref() {
            set_headers = true;
            headers = headers_tmp.iter().map(|(k,v)|{(k.as_str(),v.as_str())}).collect::<Vec<_>>();
        };
        let method = if let Some(m) = poc_req.method.as_ref(){
            m.as_str()
        } else {
            "GET"
        };
        let mut path_args = if let Some(u) = poc_req.path_args.as_ref(){
            u.as_str()
        } else {
            "/"
        };
        //println!("{:?}",header_map);   ////////////////////////////////////
        let mut is_root = false;
        if method == "GET" && ( path_args == "" || path_args == "/" ) && !set_headers{
            is_root = true;
            status_code = root_status_code;
        } else {    //否则就是非“/”请求，更新status_code，match_header，match_body
            let path_args_cache:String;
            if !path_args.starts_with("/") {
                path_args_cache = format!("/{}",path_args);
                path_args = &path_args_cache;
            };
            match method {
                "GET" => {
                    let req = fmt_req(host, port, method, path_args, headers, None);
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    //println!("{}",req);   ////////////////////////////
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    //let rsp = req.send().await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "POST" => {
                    let req_body = poc_req.req_body.as_ref();
                    let req = if req_body.is_some() {
                        let mut req_body = req_body.unwrap().clone(); 
                        req_body = req_body.replace("$HOST$", host);
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body = req_body.replace(from, to);
                            }
                        }
                        fmt_req(host, port, method, path_args, headers, Some(&req_body))
                    } else {
                        fmt_req(host, port, method, path_args, headers, None)
                    };
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    //println!("{}",req);   ////////////////////////////
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "HEAD" => {
                    let req = fmt_req(host, port, method, path_args, headers, None);
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "PUT" => {
                    let req_body = poc_req.req_body.as_ref();
                    let req = if req_body.is_some() {
                        let mut req_body = req_body.unwrap().clone(); 
                        req_body = req_body.replace("$HOST$", host);
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body = req_body.replace(from, to);
                            }
                        }
                        fmt_req(host, port, method, path_args, headers, Some(&req_body))
                    } else {
                        fmt_req(host, port, method, path_args, headers, None)
                    };
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "DELETE" => {
                    let req = fmt_req(host, port, method, path_args, headers, None);
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "PATCH" => {
                    let req_body = poc_req.req_body.as_ref();
                    let req = if req_body.is_some() {
                        let mut req_body = req_body.unwrap().clone(); 
                        req_body = req_body.replace("$HOST$", host);
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body = req_body.replace(from, to);
                            }
                        }
                        fmt_req(host, port, method, path_args, headers, Some(&req_body))
                    } else {
                        fmt_req(host, port, method, path_args, headers, None)
                    };
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "OPTIONS" => {
                    let req = fmt_req(host, port, method, path_args, headers, None);
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "TRACE" => {
                    let req = fmt_req(host, port, method, path_args, headers, None);
                    let mut req = req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            req = req.replace(from, to);
                        }
                    }
                    let rsp = http_cli(protocol, host, port, req, self.conn_timeout, self.http_timeout).await;
                    if let Ok(r) = rsp {
                        status_code = r.0;
                        match_header_not_root_cache = r.2;
                        match_body_not_root_cache = r.3;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                _ => {return None}
            };
            match_header = &match_header_not_root;
            match_body = &match_body_not_root;
        }
        let mut is_match = true;
        //println!("{}",match_header);
        //println!("{:?}",need_true);
        for k in need_true.iter() {
            match k {
                Rules::StatusCode(s) => {
                    if status_code != *s {
                        is_match = false;
                    }
                },
                Rules::Header(header_keywords) => {
                    for keyword in header_keywords.iter() {
                        if !match_header.contains(keyword) {
                            is_match = false;
                        }
                    }
                },
                Rules::Body(body_keywords) => {
                    for keyword in body_keywords.iter() {
                        if !match_body.contains(keyword) {
                            is_match = false;
                        }
                    }
                },
                Rules::Favicon(f) => {         //前面是如果有favicon_hash，才会有Rules::Favicon，所以这里能直接unwrap()
                    if favicon_hash.is_none() {
                        is_match = false;
                    } else {
                        if *f != favicon_hash.unwrap() {
                            is_match = false;
                        }
                    }
                }
            }
        }
        //println!("match? {}",is_match);
        if is_match {
            if is_root {
                if return_data {
                    return Some(Some(root_header.to_string()+root_body));
                } else {
                    return Some(None);
                }
            } else {
                if return_data {
                    return Some(Some(format!("{}{}",match_header_not_root,match_body_not_root)));
                } else {
                    return Some(None);
                }
            }
        } else {
            return None;
        }
    }

    async fn favicon_hash(&self,url:String) -> Option<i32> {
        let url = HttpUrl::new(url).unwrap();
        let host = url.host();
        let port = url.port();
        let path = url.path_args();
        let req = fmt_req(host, port, "GET", path, Vec::new(), None);
        let mut favicon_hash = None;
        if let Ok(rsp) = http_cli(url.protocol(), host,port, req, self.conn_timeout, self.http_timeout).await {
            if rsp.0 == 200 {
                let mut base64_buf = String::new();
                base64::encode_config_buf(rsp.3, base64::STANDARD, &mut base64_buf);
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
}