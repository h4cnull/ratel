use std::error::Error;
use std::time::Duration;
use reqwest::blocking::{Client,ClientBuilder,RequestBuilder};
use regex::Regex;

//use Message;
use super::result_struct::*;
use super::Message;
use super::https_banner::USER_AGENT;

use serde_json::Value;
use serde::Deserialize;
use std::sync::Arc;

use std::sync::mpsc::{SyncSender};

#[derive(Deserialize)]
pub struct FofaResult {
    pub error: bool,
    pub mode: String,
    pub page: u64,
    pub query: String,
    pub results: Vec<Vec<String>>,
    pub size: u64
}

#[derive(Deserialize)]
pub struct FofaTopQueryError {
    pub error: bool,
    pub errmsg: String
}

#[derive(Deserialize)]
pub struct FofaQueryResult {

}

pub struct QueryMatcher {
    domain_regex:Regex,
    ip_regex:Regex,
    cidr_regex:Regex,
    fofa_regex:Regex,
    zoomeye_regex:Regex
}

impl QueryMatcher {
    pub fn new() ->QueryMatcher {
        QueryMatcher {
            domain_regex: Regex::new("^(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\\.)+[a-zA-Z]+$").unwrap(),
            ip_regex: Regex::new("^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$").unwrap(),
            cidr_regex: Regex::new("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]+$").unwrap(),
            fofa_regex: Regex::new("^.*?(?: (?:&&)|(?:\\|\\|) )?\\(?[a-zA-Z](?:==)|(?:!?=)\"?.*$").unwrap(),
            zoomeye_regex: Regex::new("^\\*|(?:.*[+-]?\\(?[a-zA-Z]+:\"?).*$").unwrap()
        }
    }

    pub fn is_domain(&self,s:&str)->bool {
        self.domain_regex.is_match(s)
    }
    
    pub fn is_ip(&self,s:&str)->bool {
        self.ip_regex.is_match(s)
    }
    
    pub fn is_cidr(&self,s:&str)->bool {
        self.cidr_regex.is_match(s)
    }
    
    pub fn is_fofa(&self,s:&str)->bool {
        self.fofa_regex.is_match(s) //|| self.fofa_regex2.is_match(s) || self.fofa_regex3.is_match(s)
    }
    
    pub fn is_zoomeye(&self,s:&str)->bool {
        self.zoomeye_regex.is_match(s) //|| self.zoomeye_regex2.is_match(s)
    }
}

pub fn unverify_client(timeout:Duration)-> Client {
    let cli = ClientBuilder::new();
    let cli1 = cli.timeout(timeout);
    let cli1 = cli1.danger_accept_invalid_certs(true);
    let cli2 = cli1.danger_accept_invalid_hostnames(true);
    let cli3 = cli2.build().unwrap();
    cli3
}

pub fn http_req(req:RequestBuilder)-> Result<String,Box<dyn Error>> {
    //https://fofa.so/api/v1/search/all?email=%s&page=%d&size=%d&key=%s&qbase64=%s&fields=ip,host,title,port,protocol
    let content = req.send()?.text()?;
    Ok(content)
}

pub fn fofa_auth(fofa_email:&str,fofa_key:&str,fofa_timeout:Duration,fofa_delay:Duration)->bool {
    let cli = unverify_client(fofa_timeout);
    let auth_url = format!("https://fofa.so/api/v1/info/my?email={}&key={}",fofa_email,fofa_key);
    let mut auth_true = false;
    let mut err_msg = "[!] Fofa authentication max retries failed".to_string();
    for _ in 0..3 {
        let req_builder = cli.get(&auth_url).header("User-Agent", USER_AGENT);
        match http_req(req_builder) {
            Ok(content) => {
                if content.contains("\"email\"") && content.contains("\"username\"") {
                    auth_true = true
                } else {
                    match serde_json::from_str::<Value>(&content){
                        Ok(v) => {
                            let mut info ="unknown error";
                            if let Some(info_tmp) = v.get("errmsg") {
                                if let Some(info_tmp) = info_tmp.as_str(){
                                    info = info_tmp;
                                }
                            };
                            err_msg = format!("[!] Fofa authentication error: {}",info);
                        },
                        Err(e) => {
                            err_msg = format!("[!] Fofa authentication response is not json data: {}",e);
                        }
                    };      
                }
                break;
            },
            Err(_) => {
                std::thread::sleep(fofa_delay);
            }
        }
    }
    if !auth_true {
        println!("{}",err_msg);
    }
    return auth_true
}

#[derive(Debug,Clone,Copy)]
pub enum PassiveMod {
    Query,
    Recovery
}

pub fn fofa_search(run_mod:PassiveMod,searchs:Arc<Vec<String>>,fofa_sender:SyncSender<Message>,fofa_email:String,fofa_key:String,per_page_size:u16,fofa_timeout:Duration,passive_retries:u8,fofa_retry_delay:Duration,fofa_delay:Duration,auto_web_filter:bool) {
    let query = match run_mod {
        PassiveMod::Query => true,
        PassiveMod::Recovery => false
    };
    let mut to_the_end = true;
    let mut start_page = 1;

    let query_matcher = QueryMatcher::new();
    let cli = unverify_client(fofa_timeout);
    let auth_true = fofa_auth(&fofa_email, &fofa_key,fofa_timeout,fofa_delay);
    for search in searchs.iter() {
        let (qbase64,ss) = if query {
            if query_matcher.is_zoomeye(search) {
                //println!("{} is zoomeye",s); //////////////////////
                if !query_matcher.is_fofa(search) {   
                    continue;
                }
            }
            //search string
            let ss = if query_matcher.is_ip(search) {
                format!("ip=\"{}\"",search)
            } else if query_matcher.is_cidr(search) {
                if auto_web_filter {
                    format!("ip=\"{}\" && (protocol==\"http\" || protocol==\"https\")",search)
                } else {
                    format!("ip=\"{}\"",search)
                }
            } else if query_matcher.is_domain(search) {
                format!("domain=\"{}\" || cert=\"{}\"",search,search)
            } else {
                search.to_string()
            };
            (base64::encode(ss.as_bytes()),ss)
            //format!("https://fofa.so/api/v1/search/all?email={}&key={}&size={}&qbase64={}&fields=ip,host,title,port,protocol",fofa_email,fofa_key,per_page_size,urlencoding::encode(&qbase64))    
        } else {
            if !search.contains("https://fofa.so/") {
                continue;
            } else if search.starts_with(ERROR_PAGE) {
                to_the_end = false;
                let tmp = &search.as_str()[ERROR_PAGE.len()..];   //https://fofa.so/api......
                let tmp = tmp.split(" ").collect::<Vec<&str>>()[0];   //url
                let tmp = tmp.split("&page=").collect::<Vec<&str>>();
                start_page = tmp[1].parse().unwrap();  //page
                let tmp = tmp[0].split("&qbase64=").collect::<Vec<&str>>()[1]; //query
                let qbase64 = urlencoding::decode(tmp).unwrap();
                let ss = String::from_utf8(base64::decode(&qbase64).unwrap()).unwrap();
                (qbase64,ss)
            } else if search.starts_with(BREAK_PAGE) {
                to_the_end = true;
                let tmp = &search.as_str()[BREAK_PAGE.len()..];   //https://fofa.so/api......
                let tmp = tmp.split(" ").collect::<Vec<&str>>()[0];  //url
                let tmp = tmp.split("&page=").collect::<Vec<&str>>();
                start_page = tmp[1].parse().unwrap();  //page
                let tmp = tmp[0].split("&qbase64=").collect::<Vec<&str>>()[1];  //query
                let qbase64 = urlencoding::decode(tmp).unwrap();
                let ss = String::from_utf8(base64::decode(&qbase64).unwrap()).unwrap();
                (qbase64,ss)
            } else {
                continue;
            }  
        };
        println!("[-] Fofa searching {} ...",ss);
        let mut page_step = 0;
        loop {
            let page = start_page + page_step;
            let url = format!("https://fofa.so/api/v1/search/all?email={}&key={}&size={}&fields=ip,host,title,port,protocol&qbase64={}&page={}",fofa_email,fofa_key,per_page_size,urlencoding::encode(&qbase64),page); //format!("{}&page={}",qurl,page);
            //println!("{}",url);         ///////////////////////////////////////////////////////////////
            if !auth_true {
                fofa_sender.send(Message::Content(Box::new(
                    OtherRecord::new(OtherRecordInfo::BreakPage(format!("{} {} fofa auth failed",url,page)))
                ))).unwrap();
                break;
            }
            match retry_get(&cli, &url, None, passive_retries, fofa_retry_delay) {
                Some(content) => {
                    if let Ok(mut rst) = serde_json::from_str::<FofaResult>(&content) {
                        if page == start_page {
                            println!("[-] Fofa search {} total results {}",ss,rst.size);
                            if rst.size == 0 {
                                fofa_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::FofaNoResult(ss))))).unwrap();
                                break;
                            }
                        }
                        for _ in 0..rst.results.len() {
                            //["198.57.247.198", "https://gator3234.hostgator.com:2087", "WHM 登录", "2087", ""]
                            let mut r = rst.results.pop().unwrap();
                            //println!("{:?}",r);
                            //break;
                            let mut protocol = r.pop().unwrap();
                            let port = r.pop().unwrap().parse::<u16>().unwrap_or_else(|_|{0});
                            let title = r.pop().unwrap();
                            let host = r.pop().unwrap();
                            if host.starts_with("http://") {
                                protocol = "http".to_string();
                            } else if host.starts_with("https://"){
                                protocol = "https".to_string();
                            }
                            if protocol == "" {
                                protocol = "http".to_string();
                            }
                            let hosts = host.split(":").collect::<Vec<_>>();
                            let host = if hosts.len() == 1 {
                                hosts[0].to_string()
                            } else if hosts.len() == 2{  // https://xxxx.com
                                if hosts[1].starts_with("/") {
                                    hosts[1].replace("//", "")
                                } else {
                                    hosts[0].to_string()
                                }
                            }else { //https://xxx.com:8080
                                hosts[1].replace("//", "")
                            };
                            //println!("{}",host);/////////////////////////////
                            let ip = r.pop().unwrap();
                            fofa_sender.send(Message::Content(Box::new(PassiveRecord{
                                title,
                                host,
                                ip,
                                port,
                                protocol,
                                cert_domains: None
                            }))).unwrap();
                        }
                        if !to_the_end {
                            break;
                        }
                        if (per_page_size as u64) * page >= rst.size || per_page_size * (page as u16) == 10000 {
                            break;
                        }
                    } else if let Ok(fe) = serde_json::from_str::<FofaTopQueryError>(&content) {
                        //println!("{:?}",fe.errmsg);
                        println!("[!] Fofa search {} page {} error: {}", ss, page, fe.errmsg);
                        fofa_sender.send(Message::Content(Box::new(
                            OtherRecord::new(OtherRecordInfo::BreakPage(format!("{} {} fofa search error: {}",url,page,fe.errmsg)))
                        ))).unwrap();
                        break;
                    } else {
                        println!("[!] Fofa search {} page {} unknown error ", ss, page);
                        fofa_sender.send(Message::Content(Box::new(
                            OtherRecord::new(OtherRecordInfo::BreakPage(format!("{} {} fofa unknown error, content: {}",url,page,content)))
                        ))).unwrap();
                        break;
                    }
                },
                None => {
                    println!("[!] Fofa search {} page {} max retries", ss, page);
                    if page == start_page {
                        fofa_sender.send(Message::Content(Box::new(
                            OtherRecord::new(OtherRecordInfo::BreakPage(format!("{} {} start page max retries",url,page)))
                        ))).unwrap();
                        break;
                    } else {
                        fofa_sender.send(Message::Content(Box::new(
                            OtherRecord::new(OtherRecordInfo::ErrorPage(format!("{} {} max retries",url,page)))
                        ))).unwrap();
                    };
                }
            };
            page_step += 1;
            std::thread::sleep(fofa_delay);
        }
    }
}

pub fn retry_get(cli:&Client,url:&str,headers:Option<Vec<(&str,&str)>>,retries:u8,retry_delay:Duration)->Option<String> {
    let mut req_builder = cli.get(url).header("User-Agent", USER_AGENT);
    if let Some(headers) = headers {
        for h in headers.iter() {
            req_builder = req_builder.header(h.0, h.1)
        }
    }
    for _ in 0..=retries {
        if let Ok(content) = http_req(req_builder.try_clone().unwrap()) {
            return Some(content);
        }
        std::thread::sleep(retry_delay);
    }
    return None;
}

pub fn zoomeye_search(run_mod:PassiveMod,searchs:Arc<Vec<String>>,zoomeye_sender:SyncSender<Message>,mut zoomeye_keys:Vec<String>,zoomeye_timeout:Duration,passive_retries:u8,zoomeye_delay:Duration,auto_web_filter:bool) {
    let query = match run_mod {
        PassiveMod::Query => true,
        PassiveMod::Recovery => false
    };
    let mut to_the_end = true;
    let mut start_page = 1;

    //let title_regex = Regex::new("<(?:title|TITLE)>(.*?)</(?:title|TITLE)>").unwrap();
    let cert_domains_regex = Regex::new("Subject Alternative Name:\n.*?DNS:(.*)?\n").unwrap();
    //let domain = Regex::new("Subject:.*?CN=(.*)?\n").unwrap();   //匹配结果有可能是这样的www.baidu.com,emailAddress=sa@ag866.com
    let query_matcher = QueryMatcher::new();
    let cli = unverify_client(zoomeye_timeout);
    let mut current_key = zoomeye_keys.pop().unwrap();
    let mut key_invalid = false;
    //zoomeye_key_resources(&current_key,zoomeye_timeout,passive_retries,zoomeye_delay);
    for search in searchs.iter() {
        let (query_encoded,ss) = if query {
            if query_matcher.is_fofa(search) {
                //println!("{} is fofa",s); //////////////////////
                if !query_matcher.is_zoomeye(search) {   
                    continue;
                }
            }
            let ss = if query_matcher.is_ip(search) {
                format!("ip:\"{}\"",search)
            } else if query_matcher.is_cidr(search) {
                if auto_web_filter {
                    format!("cidr:\"{}\"+(service:\"https\" service:\"http\")",search)
                } else {
                    format!("cidr:\"{}\"",search)
                }
            } else if query_matcher.is_domain(search) {
                format!("site:\"{}\" ssl:\"{}\" hostname:\"{}\"",search,search,search)
            } else {
                search.to_string()
            };
            (urlencoding::encode(&ss),ss)
            //format!("https://api.zoomeye.org/host/search?query={}",)    
        } else {
            if !search.contains("https://api.zoomeye.org/") {
                continue;
            } else if search.starts_with(ERROR_PAGE) {
                to_the_end = false;
                let tmp = &search.as_str()[ERROR_PAGE.len()..];
                let tmp = tmp.split(" ").collect::<Vec<&str>>()[0];  //url
                let tmp = tmp.split("&page=").collect::<Vec<&str>>();
                start_page = tmp[1].parse().unwrap(); //page
                let tmp = tmp[0].split("?query=").collect::<Vec<&str>>()[1]; //query
                let ss = urlencoding::decode(tmp).unwrap();
                (tmp.to_string(),ss)
            } else if search.starts_with(BREAK_PAGE) {
                to_the_end = true;
                let tmp = &search.as_str()[BREAK_PAGE.len()..];
                let tmp = tmp.split(" ").collect::<Vec<&str>>()[0];  //url
                let tmp = tmp.split("&page=").collect::<Vec<&str>>();
                start_page = tmp[1].parse().unwrap(); //page
                let tmp = tmp[0].split("?query=").collect::<Vec<&str>>()[1]; //query
                let ss = urlencoding::decode(tmp).unwrap();
                (tmp.to_string(),ss)
            } else {
                continue;
            }  
        };
        println!("[-] Zoomeye searching {} ...",ss);
        let mut page_step = 0;
        let mut per_page_size = 0;
        let mut total:u64 = 0;
        let mut start_page_retries = 0;
        loop {
            let page = start_page + page_step;
            let url = format!("https://api.zoomeye.org/host/search?query={}&page={}",query_encoded,page);
            //println!("{}",url); //////////////////////////////
            if zoomeye_keys.len() == 0 && key_invalid {
                println!("[!] Zomeye search {} got no more valid key",ss);
                let info = format!("{} {} no more valid zoomeye key",url,page);
                zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::BreakPage(info))))).unwrap();
                break;
            }
            if total > 0 && page*per_page_size >= total { //如果存在结果（说明第一页获取成功），并且页数*每页数大于等于total，说明查询完了
                break;
            }
            if let Some(content) = retry_get(&cli, &url,Some(vec![("API-KEY",current_key.as_str())]),passive_retries,zoomeye_delay) {
                match serde_json::from_str::<ZoomeyeResult>(&content) {
                    Ok(mut rst) => {
                        //println!("content {}",content);     //////////////////////////
                        //println!("error: {:?}",rst.error);  //////////////////////////
                        if page == start_page {
                            println!("[-] Zoomeye search {} total results {}",ss,rst.total);
                            per_page_size = rst.matches.len() as u64;
                            total = rst.total;
                        }
                        if rst.matches.len() == 0 && rst.error.is_some() {
                            let err = rst.error.unwrap();
                            if err == "This page does not exist" {          //正常查询到结尾...  其实这里是没有必要的，因为前面有total > 0 && page*per_page_size >= total的判断。
                                break;
                            }
                            //未知错误
                            println!("[!] Zoomeye search {} got error {}",ss,err);
                            let info = format!("{} {} got error {}",url,page,err);
                            zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::BreakPage(info))))).unwrap();
                            break;
                        }
                        if rst.matches.len() == 0 && rst.total > 0 {
                            //key 没有额度了，重新获取额度，page不变
                            key_invalid = true;
                            println!("[!] Zoomeye key {} got no more quota!",current_key);
                            if let Some(key) = zoomeye_keys.pop() {
                                current_key = key;
                                key_invalid = false;
                                //zoomeye_key_resources(&current_key,zoomeye_timeout,passive_retries,zoomeye_delay);
                            }
                            continue;
                        }
                        if page == start_page && rst.total == 0 {
                            zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::ZoomeyeNoResult(ss))))).unwrap();
                            break;
                        }
                        page_step += 1;
                        //break;
                        for v in rst.matches.iter_mut() {
                            let ip = v.get("ip").unwrap().as_str().unwrap().to_string();
                            let host = ip.clone();
                            let value = v.get_mut("portinfo").unwrap().take();
                            let (port,protocol,title) = match serde_json::from_value::<ZoomeyePortInfo>(value) {
                                Ok(portinfo) => {
                                    match portinfo {
                                        ZoomeyePortInfo::IntPort{port,service,title} => {
                                            let title = if let Some(title) = title {
                                                title.join("")
                                            } else { "".to_string() };
                                            (port,service,title)
                                        },
                                        ZoomeyePortInfo::StrPort{port,service,title} => {
                                            let title = if let Some(title) = title {
                                                title.join("")
                                            } else { "".to_string() };
                                            (port.parse::<u16>().unwrap_or_else(|_|{0}),service,title)
                                        }
                                    }
                                },
                                Err(_) => {
                                    (0,format!("zoomeye freak \"protinfo\" result, at {}:\n{}",ip,content),"".to_string())
                                }
                            };
                            let mut cert_domains = Vec::new();
                            if let Some(ssl) = v.get("ssl") {
                                let ssl = ssl.as_str().unwrap();
                                if let Some(caps) = cert_domains_regex.captures(ssl) {
                                    if let Some(m) = caps.get(1) {
                                        let domains = m.as_str().split(", DNS:").collect::<Vec<&str>>();
                                        for d in domains {
                                            cert_domains.push(d.to_string());
                                        }
                                    };
                                }
                                /*  //证书中的CN 不一定是域名
                                if let Some(caps) = domain.captures(ssl) {
                                    if let Some(m) = caps.get(1) {
                                        let tmp = m.as_str().split(",").collect::<Vec<&str>>()[0];
                                        if query_matcher.is_domain(tmp) {
                                            host = tmp.to_string();
                                        };
                                    };
                                }
                                */
                            }
                            let cert_domains = if cert_domains.len() > 0 { Some(cert_domains) } else { None };
                            let record = PassiveRecord {
                                title,
                                host,
                                ip,
                                port,
                                protocol,
                                cert_domains
                            };
                            //println!("{:?}",record); //////////
                            zoomeye_sender.send(Message::Content(Box::new(record))).unwrap();
                        }
                        if !to_the_end {
                            break;
                        }
                    },
                    Err(_) => {
                        //不能正常解析为结果，说明key是错误的！,page不变
                        //修改current_key
                        //println!("content {}",content);
                        key_invalid = true;
                        println!("[!] Zoomeye key {} is invalid",current_key);
                        if let Some(key) = zoomeye_keys.pop() {
                            current_key = key;
                            key_invalid = false;
                            //zoomeye_key_resources(&current_key,zoomeye_timeout,passive_retries,zoomeye_delay);
                        }
                        continue;
                    }
                }
            } else {
                if page == start_page {       //如果是起始页，则重试3次
                    start_page_retries += 1;
                }
                println!("[!] Zoomeye search {} page {} max retries", ss, page);
                if start_page_retries == 3 {  //起始页重试3次失败，break
                    let info = format!("{} {} start page max retries",url,page);
                    zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::BreakPage(info))))).unwrap();
                    break;
                }
                if page != 1 {  //如果是其它页，则page+1
                    page_step += 1;
                    let info = format!("{} {} max retries",url,page);
                    zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new(OtherRecordInfo::ErrorPage(info))))).unwrap();
                }
            }
            std::thread::sleep(zoomeye_delay);
        }
    }
}

#[derive(Deserialize,Debug)]
pub struct Resources {
    pub search: u64,
    pub stats: u64,
    pub interval: String
}

#[derive(Deserialize,Debug)]
pub struct UserInfo {
    pub name: String,
    pub role: String,
    pub expired_at: String
}

#[derive(Deserialize,Debug)]
pub struct QuotaInfo {
    pub remain_free_quota: u64,
    pub remain_pay_quota: u64,
    pub remain_total_quota: u64
}

#[derive(Deserialize,Debug)]
pub struct ZoomeyeResourcesInfo {
    pub plan: String,
    pub resources: Resources, 
    pub user_info: UserInfo, 
    pub quota_info: QuotaInfo
}

#[derive(Deserialize)]
pub struct ZoomeyeResult {
    pub total:u64,
    pub available:u64,
    pub matches: Vec<Value>,
    pub facets: Value,
    pub error: Option<String>
}

#[derive(Deserialize,Debug)]
pub enum ZoomeyePort {
    Str(String),
    U16(u16)
} 

pub struct IntPortInfo {
    pub port: u16,
    pub service: String,
    pub title: Option<Vec<String>>
}

#[derive(Deserialize,Debug)]
#[serde(untagged)]
pub enum ZoomeyePortInfo {
    IntPort{ port:u16,service:String,title:Option<Vec<String>> },
    StrPort{ port:String,service:String,title:Option<Vec<String>> },
}

#[derive(Deserialize)]
pub struct ZoomeyeStringPortInfo {
    pub port: String,       //智障zoomeye, 有些返回结果 port是string类型
    pub service: String,
    pub title: Option<Vec<String>>
}

/*
fn zoomeye_key_resources(key:&str,zoomeye_timeout:Duration,retries:u8,zoomeye_delay:Duration){
    let cli = unverify_client(zoomeye_timeout);
    let url = "https://api.zoomeye.org/resources-info";
    let req_builder = cli.get(url).header("User-Agent", USER_AGENT).header("API-KEY", key);
    for _ in 0..=retries {
        if let Ok(content) = http_req(req_builder.try_clone().unwrap()) {
            let res_info = serde_json::from_str::<ZoomeyeResourcesInfo>(&content);
            match res_info {
                Ok(info) => {
                    if info.resources.search > 0 {
                        println!("[-] Zoomeye key {} is ok, remain quota {}",key,info.resources.search);
                    } else {
                        println!("[!] Zoomeye key {} got no more quota!",key);
                    }
                },
                Err(_) => {
                    println!("[!] Zoomeye key {} is invalid. content {}",key,content);
                }
            }
            break;
        }
        std::thread::sleep(zoomeye_delay);
    }  
}

pub fn zoomeye_key_check(keys:&mut Vec<String>,zoomeye_timeout:Duration,retries:u8) -> Result<String,ZoomeyeKeyError> {
    if let Some(key) = keys.pop() {
        let cli = unverify_client(zoomeye_timeout);
        let url = "https://api.zoomeye.org/resources-info";
        let req_builder = cli.get(url).header("User-Agent", USER_AGENT).header("API-KEY", key.as_str());
        for _ in 0..=retries {
            if let Ok(content) = http_req(req_builder.try_clone().unwrap()) {
                let res_info = serde_json::from_str::<ZoomeyeResourcesInfo>(&content);
                match res_info {
                    Ok(info) => {
                        if info.resources.search > 0 {
                            println!("[-] Zoomeye key {} is ok, remain quota {}",key,info.resources.search);
                            return Ok(key);
                        } else {
                            println!("[!] Zoomeye key {} got no more quota!",key);
                            return zoomeye_key_check(keys, zoomeye_timeout, retries);
                        }
                    },
                    Err(_) => {
                        println!("[!] Zoomeye key {} is invalid",key);
                        return zoomeye_key_check(keys, zoomeye_timeout, retries);
                    }
                }
            }
        }
        keys.push(key);
        return Err(ZoomeyeKeyError::MaxRetry);
    } else {
        println!("[!] No more valid zoomeye key");
        return Err(ZoomeyeKeyError::NoMore);
    }
}

pub enum ZoomeyeKeyError {
    MaxRetry,
    NoMore
}
*/