use std::collections::HashMap;
use std::time::{Duration, Instant};
use regex::{Regex,RegexBuilder};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
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
    http_client: HttpClient,
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
    pub rules:Option<PocRules>,
    pub delay:Option<usize>
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

struct HttpCheckRst {
    status_code: u16,
    raw_header: Vec<u8>,
    raw_body: Vec<u8>,
    cert_domains: Vec<String>,
    current_url: HttpUrl
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
        let mut http_client = HttpClient::default();
        let http_timeout = Duration::from_secs(conf.http_timeout);
        http_client.set_http_timeout(http_timeout);
        return Detector {
            server_regex,
            icon_regex,
            icon_href_regex,
            title_regex,
            http_client,
            http_timeout: Duration::from_secs(conf.http_timeout),
            follow_redirect: conf.follow_redirect,
            per_url_limit: conf.per_url_limit,
            disable_poc: conf.disable_poc,
            pocs,
            favicon_hash_in_pocs
        };
    }

    async fn http_check(&self,service:&str,host:&str,port:u16)-> HttpCheckRst {
        let mut code = 0;
        let mut raw_header = Vec::new();
        let mut raw_body = Vec::new();
        let mut cert_domains = vec![];
        let url = format!("{}://{}:{}/",service,host,port);
        //let r = self.http_client.get(url);
        //if r.is_err() {
        //    log::error!("{}",format!("{}://{}:{}/",service,host,port));
        //}
        //let mut req = r.unwrap();
        let mut req = self.http_client.get(url).unwrap();
        let mut next_url:Option<String> = None;
        let start = Instant::now();
        for _ in 0..MAX_REDIRECT_NUM {
            //println!("{}",String::from_utf8_lossy(&body));
            if next_url.is_some() {
                let n_url = next_url.as_ref().unwrap();
                if let Ok(tmp) = self.http_client.get(n_url.as_str().to_string()) {
                    req = tmp;
                } else {
                    break;
                }
            }
            let rst = req.send().await;
            if let Ok(rst) = rst {
                code = rst.status_code;
                raw_header = rst.raw_header;
                raw_body = rst.raw_body;
                if cert_domains.len() == 0 && rst.cert.is_some() {
                    if let Ok(tmp) = cert_parser(rst.cert.unwrap()) {
                        cert_domains = tmp;
                    };
                }
                if self.follow_redirect && (300..400).contains(&rst.status_code) {
                    if let Some(u) = rst.location {
                        if u.starts_with("/") {
                            next_url = Some(format!("{}://{}:{}{}",req.url.scheme(),req.url.host(),req.url.port(),u));
                        } else if u.starts_with("http:") || u.starts_with("https:") {
                            next_url = Some(u);
                        } else {
                            next_url = Some(format!("{}{}",req.url.url_with_path(),u));
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
            let used = Instant::now() - start;
            if used >= self.http_timeout {
                break;
            }
        }
        let current_url = req.url;
        return HttpCheckRst { status_code:code,raw_header,raw_body,current_url,cert_domains };  //end with /
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
                let check_rst = self.http_check("http", &data.host, data.port).await; 
                if check_rst.status_code > 0 {
                    data.protocol = "http".to_string();
                    data.url = Some(format!("http://{}:{}",data.host,data.port));
                    data.status_code = check_rst.status_code;
                    root_header_cache = check_rst.raw_header;
                    root_body_cache = check_rst.raw_body;
                    current_url_path = Some(check_rst.current_url);
                } else if data.port == 80 {
                    data.protocol = "http".to_string();
                    data.url = Some(format!("http://{}:{}",data.host,data.port));
                }
            }
            if data.port != 80 && data.protocol == "" {
                let mut check_rst = self.http_check("https", &data.host, data.port).await;
                if check_rst.status_code > 0 {
                    data.protocol = "https".to_string();
                    data.url = Some(format!("https://{}:{}",data.host,data.port));
                    data.status_code = check_rst.status_code;
                    root_header_cache = check_rst.raw_header;
                    root_body_cache = check_rst.raw_body;
                    current_url_path = Some(check_rst.current_url);
                    data.cert_domains.append(&mut check_rst.cert_domains);
                } else if data.port == 443 {
                    data.protocol = "https".to_string();
                    data.url = Some(format!("https://{}:{}",data.host,data.port));
                }
            } 
        } else {
            if data.protocol == "http" || data.protocol == "https" {
                data.url = Some(format!("{}://{}:{}",data.protocol,data.host,data.port));
                let mut check_rst = self.http_check(&data.protocol, &data.host, data.port).await;
                if check_rst.status_code > 0 {
                    data.status_code = check_rst.status_code;
                    root_header_cache = check_rst.raw_header;
                    root_body_cache = check_rst.raw_body;
                    current_url_path = Some(check_rst.current_url);
                    data.cert_domains.append(&mut check_rst.cert_domains);
                }
            }
        }
        
        let mut infos = Vec::new();
        let mut level = 0;
        if data.status_code > 0 {
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
                        favicon_hash = http_favicon_hash(favicon_url.unwrap(),self.http_timeout).await;
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
            let delay = poc_req.delay.unwrap_or(0);  // millisecond
            if delay != 0 {
                async_std::task::sleep(Duration::from_millis(delay as u64)).await;
            };
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
    
    async fn poc_request(&self,service:&str,host:&str,port:u16,poc_req:&PocRequest,root_status_code:u16,root_header:&str,root_body:&str,favicon_hash:Option<i32>,replace_variables:&Option<HashMap<&str,String>>,return_data:bool) -> Option<Option<String>> {
        let mut need_true = Vec::with_capacity(4);
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
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let mut req = self.http_client.get(url).unwrap();
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "POST" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    //需要先替换body的变量, 创建RawRequest时计算Content-Length
                    let req_body = poc_req.req_body.as_ref();
                    let mut req_body_str:String;
                    let mut req = if req_body.is_some() {
                        req_body_str = req_body.unwrap().replace("$HOST$", host); 
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body_str = req_body_str.replace(from, to);
                            }
                        }
                        self.http_client.request(HTTPMethod::POST,url,Some(&req_body_str)).unwrap()
                    } else {
                        self.http_client.request(HTTPMethod::POST,url,None).unwrap()
                    };
                    //如果指定的headers中包含了host,user-agnet,connection,content-length,则会替换为指定的值
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "HEAD" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let mut req = self.http_client.request(HTTPMethod::HEAD,url,None).unwrap();
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "PUT" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let req_body = poc_req.req_body.as_ref();
                    let mut req_body_str:String;
                    let mut req = if req_body.is_some() {
                        req_body_str = req_body.unwrap().replace("$HOST$", host);
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body_str = req_body_str.replace(from, to);
                            }
                        }
                        self.http_client.request(HTTPMethod::PUT,url,Some(&req_body_str)).unwrap()
                    } else {
                        self.http_client.request(HTTPMethod::PUT,url,None).unwrap()
                    };
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "DELETE" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let mut req = self.http_client.request(HTTPMethod::DELETE,url,None).unwrap();
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "PATCH" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let req_body = poc_req.req_body.as_ref();
                    let mut req_body_str:String;
                    let mut req = if req_body.is_some() {
                        req_body_str = req_body.unwrap().replace("$HOST$", host);
                        if replace_variables.is_some() {
                            let reps = replace_variables.as_ref().unwrap();
                            for (from,to) in reps {
                                req_body_str = req_body_str.replace(from, to);
                            }
                        }
                        self.http_client.request(HTTPMethod::PATCH,url,Some(&req_body_str)).unwrap()
                    } else {
                        self.http_client.request(HTTPMethod::PATCH,url,None).unwrap()
                    };
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                }
                "OPTIONS" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let mut req = self.http_client.request(HTTPMethod::OPTIONS,url,None).unwrap();
                    let mut raw_req = req.fmt_req();
                    req.set_headers(headers);
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
                        match_header_not_root = String::from_utf8_lossy(&match_header_not_root_cache);
                        match_body_not_root = String::from_utf8_lossy(&match_body_not_root_cache);
                    };
                },
                "TRACE" => {
                    let url = format!("{}://{}:{}{}",service,host,port,path_args);
                    let mut req = self.http_client.request(HTTPMethod::TRACE,url,None).unwrap();
                    req.set_headers(headers);
                    let mut raw_req = req.fmt_req();
                    raw_req = raw_req.replace("$HOST$", host);
                    if replace_variables.is_some() {
                        let reps = replace_variables.as_ref().unwrap();
                        for (from,to) in reps {
                            raw_req = raw_req.replace(from, to);
                        }
                    }
                    let rsp = req.send_req(raw_req).await;
                    if let Ok(r) = rsp {
                        status_code = r.status_code;
                        match_header_not_root_cache = r.raw_header;
                        match_body_not_root_cache = r.raw_body;
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
}