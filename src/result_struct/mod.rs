use std::net::ToSocketAddrs;
use std::cmp::PartialEq;

#[derive(PartialEq)]
pub enum RecordType {
    Active,
    Passive,
    Other
}

pub trait Record {
    fn record(&self) -> Option<String>;
    fn record_type(&self) -> RecordType;   //主动扫描结果，需要发送到result进行盲识别（强制视为http或https）
    fn title(&self) -> &str {
        ""
    }
    fn host(&self) -> &str {
        ""
    }
    fn ip(&self) -> &str {
        ""
    }
    fn port(&self) -> u16 {
        0
    }
    fn protocol(&self) -> &str {
        ""
    }
    fn cert_domains(&mut self) -> Option<Vec<String>> {
        None
    }
}

pub enum OtherRecordInfo {
    NoOpenPort(String),
    UnknownHost(String),
    ErrorPage(String),
    BreakPage(String),
    FofaNoResult(String),
    FofaSensitive(String),
    ZoomeyeNoResult(String),
    Padding
}
pub struct OtherRecord {
    info:OtherRecordInfo
}

impl OtherRecord {
    pub fn new(info: OtherRecordInfo) -> OtherRecord {
        OtherRecord {
            info
        }
    }
}

pub static NO_OPEN_PORT:&'static str = "no open port: ";
pub static UNKNOWN_HOST:&'static str = "unknown host: ";
pub static ERROR_PAGE:&'static str = "error page: ";
pub static BREAK_PAGE:&'static str = "break page: ";
pub static FOFA_NO_RESULT:&'static str = "fofa no result: ";
pub static FOFA_SENSITIVE:&'static str = "fofa sensitive keyword: ";
pub static ZOOMEYE_NO_RESULT:&'static str = "zoomeye no result: ";

impl Record for OtherRecord {
    fn record(&self) -> Option<String> {
        match &self.info {
            OtherRecordInfo::NoOpenPort(info) => Some(format!("{}{}",NO_OPEN_PORT,info)),
            OtherRecordInfo::UnknownHost(info)=> Some(format!("{}{}",UNKNOWN_HOST,info)),
            OtherRecordInfo::ErrorPage(info) => Some(format!("{}{}",ERROR_PAGE,info)),
            OtherRecordInfo::BreakPage(info) => Some(format!("{}{}",BREAK_PAGE,info)),
            OtherRecordInfo::FofaNoResult(info) => Some(format!("{}{}",FOFA_NO_RESULT,info)),
            OtherRecordInfo::FofaSensitive(info) => Some(format!("{}{}",FOFA_SENSITIVE,info)),
            OtherRecordInfo::ZoomeyeNoResult(info) => Some(format!("{}{}",ZOOMEYE_NO_RESULT,info)),
            OtherRecordInfo::Padding => None
        }
    }
    fn record_type(&self) -> RecordType {
        RecordType::Other
    }
}

pub struct ActiveRecord {
    pub host:String,
    pub ip:String,
    pub port:u16,
}

#[derive(Debug)]
pub struct PassiveRecord {
    pub title:String,
    pub host:String,
    pub ip:String,
    pub port:u16,
    pub protocol:String,
    pub cert_domains: Option<Vec<String>>
}

impl Record for ActiveRecord {
    fn record(&self) -> Option<String> {
        Some(format!("{}:{}",&self.host,self.port))
    }
    fn record_type(&self) ->RecordType {
        RecordType::Active
    }
    fn host(&self) -> &str {
        &self.host
    }
    fn ip(&self) -> &str {
        &self.ip
    }
    fn port(&self) -> u16 {
        self.port
    }
}

impl Record for PassiveRecord {
    fn record(&self) -> Option<String> {
        Some(format!("{}:{}",&self.host,self.port))
    }
    fn record_type(&self) -> RecordType {
        RecordType::Passive
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn host(&self) -> &str {
        &self.host
    }
    fn ip(&self) -> &str {
        &self.ip
    }
    fn port(&self) -> u16 {
        self.port
    }
    fn protocol(&self) -> &str {
        &self.protocol
    }
    fn cert_domains(&mut self) -> Option<Vec<String>> {
        self.cert_domains.take()
    }
}

//title,host,ip,port,protocol,url,infos,status_code,cert_domains,is_assets,level

pub fn url_to_passive_record(url:&str)-> Option<PassiveRecord> {
    let tmp = url.trim().split("://").collect::<Vec<&str>>();
    if tmp.len() == 2 {
        let host_tmp = tmp[1].split("/").collect::<Vec<&str>>()[0];
        let host_tmp = host_tmp.split(":").collect::<Vec<&str>>();
        let host = host_tmp[0].to_string();
        let (port,protocol) = match tmp[0] {
            "http" => {
                let port = if host_tmp.len() == 1 {
                    80
                } else {
                    host_tmp[1].parse::<u16>().unwrap_or_else(|_|{ 0 })
                };
                (port,"http".to_string())
            },
            "https" => {
                let port = if host_tmp.len() == 1 {
                    443
                } else {
                    host_tmp[1].parse::<u16>().unwrap_or_else(|_|{ 0 })
                };
                (port,"https".to_string())
            },
            _ => { return None; }
        };
        if port > 0 {
            let mut ip = "".to_string();
            let addr = format!("{}:{}", host, port);
            if let Ok(mut socket_addrs) = addr.to_socket_addrs() {
                let socket_addr = socket_addrs.next().unwrap();
                ip = socket_addr.ip().to_string()
            }
            return Some(PassiveRecord {
                title:"".to_string(),
                host,
                ip,
                port,
                protocol,
                cert_domains: None
            });
        } else {
            return None;
        }
    } else {
        return None;
    }
}

#[derive(Debug)]
pub struct Data {             //最终结果
    pub title:String,
    pub host:String,
    pub ip:String,
    pub port:u16,
    pub protocol:String,
    pub url:Option<String>,
    pub infos:Vec<String>,    //cms midware vuln...
    pub status_code: u16,     //http status code，存在则说明可访问
    pub cert_domains: Vec<String>,
    pub is_assets: bool,      //明确的资产
    pub favicon:Option<i32>,
    pub level: u8,            //级别
}

#[derive(Debug)]
pub struct NoNeedCheckDataCache {
    pub title:String,
    pub cert_domains: Vec<String>
}

pub enum CellType<'a> {
    Str(&'a str),
    Strin(String),
    Num(u16),
    Boolean(bool)
}

use csv::{Writer,Reader};
use std::error::Error;

pub static RST_COLS:&[&str] = &["title","host","ip","port","protocol","url","status code","infos","cert domains","is_assets","favicon","level"];

pub fn write_data_to_csv(wtr:&mut Writer<Vec<u8>>,data:&Data)->Result<(),Box<dyn Error>> {
    wtr.write_field(&data.title)?;
    wtr.write_field(&data.host).unwrap();
    wtr.write_field(&data.ip).unwrap();
    wtr.write_field(data.port.to_string()).unwrap();
    wtr.write_field(&data.protocol).unwrap();
    wtr.write_field(if data.url.is_some() { data.url.as_ref().unwrap() } else {""}).unwrap();
    wtr.write_field(&data.status_code.to_string()).unwrap();
    wtr.write_field(&format!("{:?}",data.infos)).unwrap();
    wtr.write_field(&format!("{:?}",data.cert_domains)).unwrap();
    wtr.write_field(&data.is_assets.to_string()).unwrap();
    wtr.write_field( if data.favicon.is_some() {data.favicon.unwrap().to_string() } else { String::new() }).unwrap();
    wtr.write_field(&data.level.to_string()).unwrap();
    wtr.write_record(None::<&[u8]>).unwrap();
    wtr.flush().unwrap();
    Ok(())
}

pub fn read_csv_to_excludes(excludes:&mut String,ef:&str) {
    let csv_reader = Reader::from_path(&ef);
    match csv_reader {
        Ok(mut reader) => {
            let mut line_num = 1;
            for result in reader.records() {
                if line_num == 1 {
                    line_num += 1;
                    continue;
                }
                if let Ok(record) = result {
                    let items = record.iter().collect::<Vec<&str>>();
                    if items.len() >= 5 {
                        let mut host_port = format!("{}:{} ",items[1],items[3]);
                        let protocol = items[4];
                        if protocol == "http" || protocol == "https" {       //有的端口http https都可以访问，所以这里需要加上协议，否则可能跳过一些链接！
                            host_port = format!("{}{}",protocol,host_port)
                        }
                        excludes.push_str(&host_port);
                    }
                }
                // else {
                //    println!("Read exclude file {} line {}  error.",ef,line_num);
                //};
            }
        },
        Err(e) => {
            println!("[!] Read exclude file {} error:{:?}.",ef,e.kind());
        }
    };
}