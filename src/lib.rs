use clap::{App, AppSettings, Arg, ErrorKind};
use std::fs;
use regex::Regex;
use std::process::exit;
use serde::Deserialize;
use chrono::prelude::*;
use rand::prelude::*;

mod ports_parser;
use ports_parser::PortsParser;

mod passive;
pub use passive::*;

mod https_banner;
pub use https_banner::*;

mod result_struct;
pub use result_struct::*;

mod active;
pub use active::*;

mod detect_mod;
pub use detect_mod::*;

static CONFIG_FILE:&'static str = "config";
static CONFIG_TOML:&'static str = "#toml config file
fofa_enable = true
fofa_email = ''
fofa_key = ''
fofa_per_page_size = 1000
fofa_timeout = 10
fofa_retry_delay = 1
fofa_delay = 0       #second

zoomeye_enable = true
zoomeye_keys = []
#zoomeye_keys = ['key1','key2']
zoomeye_timeout = 10
zoomeye_delay = 2   #second

auto_web_filter = true  #搜索cidr时自动添加http过滤条件
passive_retries = 3

scanports = '80-89,443,444,555,666,777,888,999,1000-1100,6000-6100,6666,7000-7100,8000-8100,8800-8900,9000-9100,9999,10000-10100,20000-20100'
async_scan_limit = 1000

conn_timeout = 2500     #millisecond
conn_retries = 3        #主动扫描重试次数，确保可靠性
write_timeout = 1500
read_timeout = 3000
redirect_times = 2      #跟随重定向次数, 0不重定向

pocs_json_path = '.\\pocs.json'
detect_limit = 100   # 不同ip:port地址探测时的并发数量限制
poc_limit = 10       # 对某个url进行poc验证时的并发数量限制，过高的数量可能被waf封锁
#注意limit值过高会超过io瓶颈，影响准确性，默认100*10，并发不超过1000，如果是主动扫描，则并发不会超过1000+1000(async_scan_limit)，在linux下可能会出现too many open files!。

print_level = 0   #输出级别，默认0，全部打印。poc的level字段可设置该poc的级别，不设置则为0";

#[derive(Deserialize)]
struct TomlConf {
    fofa_enable: bool,
    fofa_email: String,
    fofa_key: String,
    fofa_per_page_size: u16,
    fofa_timeout: u64,
    fofa_retry_delay: u8,
    fofa_delay: u8,
    zoomeye_enable: bool,
    zoomeye_keys: Vec<String>,
    zoomeye_timeout: u64,
    zoomeye_delay: u8,
    auto_web_filter: bool,
    passive_retries: u8,
    scanports: String,
    async_scan_limit: u16,
    conn_timeout: u64,
    conn_retries: u8,
    write_timeout: u64,
    read_timeout: u64,
    redirect_times: u8,
    pocs_json_path: String,
    detect_limit: u16,
    poc_limit: u16,
    print_level: u8
}

#[derive(Debug)]
pub struct PassiveConfig {
    pub run_mod: PassiveMod,
    pub searchs: Vec<String>,            //搜索字符串
    pub exclude_files: Vec<String>,
    pub fofa_enable: bool,
    pub fofa_email: String,
    pub fofa_key: String,
    pub fofa_per_page_size: u16,
    pub fofa_timeout: u64,
    pub fofa_retry_delay: u8,
    pub fofa_delay: u8,
    pub zoomeye_enable: bool,
    pub zoomeye_keys: Vec<String>,
    pub zoomeye_timeout: u64,
    pub zoomeye_delay: u8,
    pub auto_web_filter: bool,
    pub passive_retries: u8
}

#[derive(Debug)]
pub struct ActiveConfig {
    pub targets: Vec<String>,
    pub exclude_files: Vec<String>,
    pub async_scan_limit: u16,
    pub scan_ports: Vec<u16>,
    pub conn_timeout: u64,
    pub conn_retries: u8,
}

#[derive(Debug)]
pub struct UrlsConfig {
    pub urls: Vec<String>,                 //从urls文件读取
    pub exclude_files: Vec<String>
}

#[derive(Debug)]
pub struct ResultConfig {                   //处理结果的配置
    pub pocs_file: String,
    pub conn_timeout: u64,
    pub conn_retries: u8,
    pub write_timeout: u64,
    pub read_timeout: u64,
    pub redirect_times: u8,
    pub poc_exclude_files: Vec<String>,         //排除文件
    pub disable_poc: bool,
    pub detect_limit: u16,                  //url limit
    pub poc_limit: u16,
    pub it_assets: (Vec<String>,Vec<String>),  //资产, ([domain],[ip])
    pub print_level: u8,
    pub output_file_name: String
}

#[derive(Debug)]
pub enum Config {
    Passive(PassiveConfig),
    Active(ActiveConfig),
    Urls(UrlsConfig)
}

pub enum Message {
    Content(Box<dyn Record + Send>),
    Finished
}

fn rand_string(len:usize)-> String {
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let chars_len = chars.len();
    let mut rng = rand::thread_rng();
    let mut rst = Vec::with_capacity(len);
    for _ in 0..len {
        let c = chars[rng.gen_range(0..chars_len)];
        rst.push(c);
    }
    String::from_utf8(rst).unwrap()
}


pub fn get_config()-> (ResultConfig,Config) {
    let app = App::new("Ratel").settings(&vec![AppSettings::DisableVersion,AppSettings::DisableHelpSubcommand])
    .help(" Usage: Ratel -s | -t | -f file < --passive | --active | --urls | --recovery >
 Options:
    -s,--string  <string>                 被动搜索字符串(例如: domain=\\\"example.com\\\"，注意命令行转义\"\\\")
    
    -t,--targets <ip,domain,cidr,...>     主动扫描指定目标主机(逗号分隔主机)
    
    -f,--file    <file>                   从文件读取(换行分隔)
                 --passive                被动信息搜集
                 --active                 将文件视为主机列表进行主动扫描
                 --urls                   将文件视为url列表进行探测
                 --recovery               从notice结果文件中恢复error page和break page查询

    -o,--output        <filename>         输出文件名前缀（默认为当前时间+5随机字符，结果包含xxx_result.xlsx，xxx_result_notice.txt）
    -e,--exclude       <files1,..>        被动搜索，主动扫描，url探测时排除的文件，逗号分隔多个文件
    --poc-exclude      <files1,..>        poc探测时的排除文件(不同任务会存在相同的资产，而poc探测是耗时的，须是Ratel输出的xlsx结果文件，逗号分隔多个文件)
    --disable-poc                         禁用poc探测
    -h,--help                             打印帮助")
    .arg(Arg::with_name("passive")
        .conflicts_with("active")
        .conflicts_with("targets")        //targets  配合active参数
        .conflicts_with("recovery")
        .takes_value(false)
        .long("passive")
    )
    .arg(Arg::with_name("active")
        .conflicts_with("search_string")  //search_string 配合的passive参数
        .conflicts_with("urls")
        .takes_value(false)
        .long("active")
    )
    .arg(Arg::with_name("urls")
        .conflicts_with("passive")
        .conflicts_with("active")
        .conflicts_with("recovery")
        .conflicts_with("targets")        //targets  配合active参数
        .conflicts_with("search_string")  //search_string 配合的passive参数 
        .takes_value(false)
        .long("urls"))
    .arg(Arg::with_name("recovery")
        .conflicts_with("passive")
        .conflicts_with("active")
        .conflicts_with("targets")        //targets  配合active参数
        .conflicts_with("search_string")
        .takes_value(false)
        .long("recovery")
    )
    .arg(Arg::with_name("search_string")
        .short("s")
        .long("string")
        .takes_value(true)
        .conflicts_with("targets"))
    .arg(Arg::with_name("targets")
        .short("t")
        .long("targets")
        .takes_value(true))
    .arg(Arg::with_name("file_list")
        .short("f")
        .long("file")
        .takes_value(true)
        .required_unless_one(&vec!["search_string","targets"]))
    .arg(Arg::with_name("output")
        .short("o")
        .long("output")
        .takes_value(true))
    .arg(Arg::with_name("exclude_files")
        .short("e")
        .long("exclude")
        .takes_value(true))
    .arg(Arg::with_name("poc_exclude_files")
        .long("poc-exclude")
        .takes_value(true))
    .arg(Arg::with_name("disable_poc")
        .long("disable-poc")
        .takes_value(false));
    let app_matches = app.get_matches_safe().unwrap_or_else(|e| {
        //println!("{}",e.message);
        match e.kind {
            ErrorKind::HelpDisplayed => {
                println!("{}",e.message);
            },
            ErrorKind::ArgumentConflict => {
                println!("参数冲突 使用-h 打印帮助");
            },
            ErrorKind::UnexpectedMultipleUsage => {
                println!("参数重复 使用-h 打印帮助");
            },
            ErrorKind::EmptyValue => {
                println!("参数值为空 使用-h 打印帮助");
            },
            ErrorKind::MissingRequiredArgument => {
                println!("缺少必须的参数<-s|-t|-f> 使用-h 打印帮助");
            },
            _ => {
                println!("{:?} 使用-h 打印帮助",e.kind);
            }
        }
        exit(-1);        
    });

    let exclude_files = if let Some(ef) =  app_matches.value_of("exclude_files") {
        ef.split(',').map(|s|{s.to_string()}).collect::<Vec<String>>()
    } else {
        vec![]
    };

    let poc_exclude_files = if let Some(ef) =  app_matches.value_of("poc_exclude_files") {
        ef.split(',').map(|s|{s.to_string()}).collect::<Vec<String>>()
    } else {
        vec![]
    };

    let disable_poc = app_matches.is_present("disable_poc");
    let s = fs::read_to_string(CONFIG_FILE).unwrap_or_else(|e| {
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                println!("[-] Not found config file \"{}\",ratel will creating it,using defalut config...",CONFIG_FILE);
                fs::write(CONFIG_FILE,CONFIG_TOML).unwrap_or_else(|e|{
                    println!("[-] Can not create config file: {:?}",e.kind());
                });
            },
            _ => {
                println!("[-] Reading config file \"{}\" error: {:?},using defalut config...",CONFIG_FILE,e.kind());
            }
        };
        CONFIG_TOML.to_string()
    });
    let toml_conf = toml::from_str::<TomlConf>(&s).unwrap_or_else(|e|{
        println!("[!] Parse onfig file \"{}\" error: {}",CONFIG_FILE,e.to_string());
        exit(-1);
    });

    let now = Local::now();
    let output_file_name = if let Some(fname) =  app_matches.value_of("output") {
        fname.to_string()
    } else {
        now.format("%Y-%m%d-%H%M-").to_string() + &rand_string(5)
    };
    
    let mut all = Vec::new();
    if let Some(list_file)= app_matches.value_of("file_list") {
        match read_file_to_list(list_file) {
            Ok(mut content) => {
                all.append(&mut content);
            },
            Err(ekind) => {
                println!("[!] Read file list {} error: {:?}",list_file,ekind);
                exit(-1);
            }
        }
    };
    let mut passive = false;
    let mut active = false;
    if let Some(s) = app_matches.value_of("search_string") {
        passive = true;
        all.push(s.to_string());
    } else if let Some(s) = app_matches.value_of("targets") {
        active = true;
        all.push(s.to_string());
    };

    let domain_regex = Regex::new("^(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\\.)+[a-zA-Z]+$").unwrap();
    let ip_regex = Regex::new("^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$").unwrap();
    let cidr_regex = Regex::new("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]+$").unwrap();
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    //提取ip和domain，以此在结果中标记资产
    for i in all.iter() {
        if domain_regex.is_match(i) {
            //println!("{}",i); ////////////////////////////
            domains.push(i.to_string());
        }
        if ip_regex.is_match(i) || cidr_regex.is_match(i) {
            //println!("{}",i); ////////////////////////////
            ips.push(i.to_string());
        }
    }
    let rst_config = ResultConfig {
        pocs_file: toml_conf.pocs_json_path,
        conn_timeout: toml_conf.conn_timeout,
        conn_retries: toml_conf.conn_retries,
        write_timeout: toml_conf.write_timeout,
        read_timeout: toml_conf.read_timeout,
        redirect_times: toml_conf.redirect_times,
        poc_exclude_files,
        disable_poc,
        detect_limit: toml_conf.detect_limit,
        poc_limit: toml_conf.poc_limit,
        it_assets:(domains,ips),
        print_level: toml_conf.print_level,
        output_file_name
    };

    let mut run_mod = PassiveMod::Query;
    if app_matches.is_present("recovery") {
        run_mod = PassiveMod::Recovery;
        passive = true;
    }
    if passive || app_matches.is_present("passive") {
        //if all.len() == 0 {
        //    exit(-1);
        //};
        return (rst_config,Config::Passive(PassiveConfig{
            run_mod,
            searchs: all,
            exclude_files,
            fofa_enable: toml_conf.fofa_enable,
            fofa_email: toml_conf.fofa_email,
            fofa_key: toml_conf.fofa_key,
            fofa_per_page_size: toml_conf.fofa_per_page_size,
            fofa_timeout: toml_conf.fofa_timeout,
            fofa_retry_delay: toml_conf.fofa_retry_delay,
            fofa_delay: toml_conf.fofa_delay,
            zoomeye_enable: toml_conf.zoomeye_enable,
            zoomeye_keys: toml_conf.zoomeye_keys,
            zoomeye_timeout: toml_conf.zoomeye_timeout,
            zoomeye_delay: toml_conf.zoomeye_delay,
            auto_web_filter: toml_conf.auto_web_filter,
            passive_retries: toml_conf.passive_retries,
        }));
    } else if active || app_matches.is_present("active") {
        let port_parser = PortsParser::new();
        let scan_ports = port_parser.parse_ports_string(&toml_conf.scanports).unwrap_or_else(|e|{
            println!("[!] Config \"scanports\" not correct: {}",e);
            exit(-1);
        });
        if all.len() == 0 {
            exit(-1);
        }
        return (rst_config,Config::Active(ActiveConfig{
                targets: all,
                exclude_files,
                async_scan_limit:toml_conf.async_scan_limit,
                scan_ports,
                conn_timeout: toml_conf.conn_timeout,
                conn_retries: toml_conf.conn_retries
        }));
    } else if app_matches.is_present("urls") {
        return (rst_config,Config::Urls(UrlsConfig {
            urls: all,
            exclude_files
        }));
    } else {
        println!("--passive | --active | --urls | --recovery选择模式");
        exit(-1);
    }
}

fn read_file_to_list(file_name:&str) -> Result<Vec<String>,std::io::ErrorKind> {
    match fs::read_to_string(file_name) {
        Ok(content) => {
            let mut rst = Vec::new();
            let lines = content.split("\n").map(|s|{s.trim()}).collect::<Vec<&str>>();
            for l in lines {
                if l != "" {
                    rst.push(l.to_string());
                }
            }
            return Ok(rst);
        },
        Err(e)=> {
            return Err(e.kind());
        }
    }
}

pub fn read_excludes(exclude_files:Vec<String>) -> Vec<String> {
    let mut rst = Vec::new();
    for ef in exclude_files.iter() {
        match fs::read_to_string(ef) {
            Ok(content) => {
                let lines = content.split("\n").map(|s|{s.trim()}).collect::<Vec<&str>>();
                for line in lines {
                    if line != "" {
                        rst.push(line.to_string());
                    }
                }
            },
            Err(e) => {
                println!("[!] Read exlcude file {} error: {:?}",ef,e.kind());
            }
        }
    };
    return rst;
}

#[cfg(test)]
mod tests {
    use super::passive::QueryMatcher;
    use regex::Regex;
    #[test]
    fn fofa_zoomeye() {
        /*
        let test1 = Regex::new("(?:&&)|(?:\\|\\|)").unwrap();
        println!("&& {}",test1.is_match("&&"));
        println!("|| {}",test1.is_match("||"));
        let test2 = Regex::new("^.*?(?: (?:&&)|(?:\\|\\|) )?.*$").unwrap();
        println!("' && ' {}",test2.is_match(" && "));
        println!("' || ' {}",test2.is_match(" || "));
        println!("m {}",test2.is_match("m"));
        */
        println!("fofa regex test...");
        let fofa_regex = Regex::new("^.*?(?: (?:&&)|(?:\\|\\|) )?\\(?[a-zA-Z](?:==)|(?:!?=)\"?.*$").unwrap();
        let s1 = "xxx country=\"CN\" region=\"HK\"";
        let s2 = "title=xxx || xxx";
        let s3 = "\"xxx\" title=\"xxx\"";
        let s4 = "xxx || (domain=xxx && title=\"xxx\")";
        println!("{} {}",s1,fofa_regex.is_match(s1));
        println!("{} {}",s2,fofa_regex.is_match(s2));
        println!("{} {}",s3,fofa_regex.is_match(s3));
        println!("{} {}",s4,fofa_regex.is_match(s4));

        println!("\nzoomeye regex test...");
        let zoomeye_regex = Regex::new("^\\*|(?:.*[+-]?\\(?[a-zA-Z]+:\"?).*$").unwrap();
        let s5 = "xxx domain:\"CN\"";
        let s6 = "title:xxx -title:xxx";
        let s7 = "\"xxx\"+title:\"xxx\"";
        let s8 = "*xxx";
        let s9 = "domain:xxx-(title:xxx+title:\"xxx\")";
        
        println!("{} {}",s5,zoomeye_regex.is_match(s5));
        println!("{} {}",s6,zoomeye_regex.is_match(s6));
        println!("{} {}",s7,zoomeye_regex.is_match(s7));
        println!("{} {}",s8,zoomeye_regex.is_match(s8));
        println!("{} {}",s9,zoomeye_regex.is_match(s9));

        println!("\nfofa regex test zoomeye...");
        println!("{} {}",s5,fofa_regex.is_match(s5));
        println!("{} {}",s6,fofa_regex.is_match(s6));
        println!("{} {}",s7,fofa_regex.is_match(s7));
        println!("{} {}",s8,fofa_regex.is_match(s8));
        println!("{} {}",s9,fofa_regex.is_match(s9));
        
        println!("\nzoomeye regex test fofa");
        println!("{} {}",s1,zoomeye_regex.is_match(s1));
        println!("{} {}",s2,zoomeye_regex.is_match(s2));
        println!("{} {}",s3,zoomeye_regex.is_match(s3));
        println!("{} {}",s4,zoomeye_regex.is_match(s4));
        
        println!("\nspace test");
        let s10 = "xxx xxx xxx";
        println!("fofa {} {}",s10,fofa_regex.is_match(s10));
        println!("zoomeye {} {}",s10,zoomeye_regex.is_match(s10));
    }
}