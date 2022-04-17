use std::fs;
use std::io::Write;
use std::thread;
use std::time::Duration;
use std::sync::{mpsc,Arc};
use std::sync::mpsc::{Receiver, SyncSender};
use std::collections::HashMap;
use csv::Writer;

use async_std::task::block_on;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use dns_lookup::lookup_host;
use cidr_utils::cidr::IpCidr;
use cidr_utils::num_bigint::ToBigUint;

use ratel::*;
use ratel::RecordType::Other;

fn passive(conf:PassiveConfig,result_sender:SyncSender<Message>) {
    if conf.searchs.len() == 0 {
        println!("[!] Passive search got nothing input");
        return;
    };
    let fofa_email = conf.fofa_email;
    let fofa_key = conf.fofa_key;
    let fofa_timeout = Duration::from_secs(conf.fofa_timeout);
    let fofa_retry_delay = Duration::from_secs(conf.fofa_retry_delay as u64);
    let fofa_delay = Duration::from_secs(conf.fofa_delay as u64);

    let zoomeye_keys = conf.zoomeye_keys;
    let zoomeye_timeout = Duration::from_secs(conf.zoomeye_timeout);
    let zoomeye_delay = Duration::from_secs(conf.zoomeye_delay as u64);

    let es = read_excludes(conf.exclude_files);
    let mut searchs = Vec::new();
    for s in conf.searchs.iter() {
        if !es.contains(s) {
            searchs.push(s.clone());
        }
    }
    drop(conf.searchs);
    drop(es);
    let searchs1 = Arc::new(searchs);
    let searchs2 = Arc::clone(&searchs1);

    let fofa_sender = result_sender.clone();
    let zoomeye_sender = result_sender.clone();

    let mut handlers = Vec::new();
    if conf.fofa_enable {
        if fofa_email != "" && fofa_key != "" {
            handlers.push(Some(thread::spawn(move||{
                fofa_search(conf.run_mod,searchs1,fofa_sender,fofa_email, fofa_key, conf.fofa_per_page_size, fofa_timeout,conf.passive_retries,fofa_retry_delay,fofa_delay,conf.auto_web_filter);
            })));
        } else {
            println!("[-] Fofa auth info not set... pass fofa query");
        }
    } else {
        println!("[-] Fofa disabled");
    }
    
    if conf.zoomeye_enable {
        if zoomeye_keys.len() > 0 {
            handlers.push(Some(thread::spawn(move||{
                zoomeye_search(conf.run_mod,searchs2,zoomeye_sender,zoomeye_keys,zoomeye_timeout,conf.passive_retries,zoomeye_delay,conf.auto_web_filter);
                //zoomeye_sender.send(Message::Content(Box::new(OtherRecord::new("zoomeye finished".to_string())))).unwrap();
            })));
        } else {
            println!("[-] Zoomeye keys not set... pass zoomeye query");
        }
    } else {
        println!("[-] Zoomeye disabled");
    }
    for h in handlers.iter_mut() {
        h.take().unwrap().join().unwrap();
    }
    result_sender.send(Message::Finished).unwrap();   
}

async fn active(conf:ActiveConfig,result_sender:SyncSender<Message>) {
    let start_time = std::time::SystemTime::now();
    let mut target_iter = TargetIter::new();
    let mut open_records = Vec::new();          //有开放端口的主机
    if conf.targets.len() == 0 {
        println!("[!] Active port scan got nothing input");
        return;
    };
    let es = read_excludes(conf.exclude_files);
    for t in conf.targets.iter() {
        if es.contains(t) {
            continue;
        }
        if t.contains("/") {
            if let Ok(cidr) = IpCidr::from_str(t) {
                target_iter.append_cidr(cidr);
            } else {
                let info = t.to_string();
                println!("[-] Unknown host {}",t);
                result_sender.send(Message::Content(Box::new(
                    OtherRecord::new(OtherRecordInfo::UnknownHost(info))
                ))).unwrap();
            }
        } else {
            match lookup_host(t) {
                Ok(h) => {
                    let host = Host{
                        host: t.to_string(),
                        ip:h[0].to_string()
                    };
                    target_iter.append(host);
                },
                Err(_) => {
                    let info = t.to_string();
                    println!("[-] Unknown host {}",t);
                    result_sender.send(Message::Content(Box::new(
                        OtherRecord::new(OtherRecordInfo::UnknownHost(info))
                    ))).unwrap();
                }
            }
        }
    }
    drop(conf.targets);
    drop(es);
    let targets_num = target_iter.total();
    if targets_num == &0.to_biguint().unwrap() {
        println!("[-] Active scan: no valid host.");
        return;
    };
    let ports_num = &conf.scan_ports.len().to_biguint().unwrap();
    println!("[-] Active scan: hosts:{} ports:{} total:{} limit:{}",targets_num,ports_num,targets_num*ports_num,conf.async_scan_limit);
    let mut active_record_iter = ActiveRecordIter::new(target_iter,conf.scan_ports).unwrap();
    let mut ftrs = FuturesUnordered::new();
    for _ in 0..conf.async_scan_limit {
        if let Some(record) = active_record_iter.next() {
            ftrs.push(scan_port(record,Duration::from_millis(conf.conn_timeout),conf.conn_retries));
        }
    }
    while let Some(record) = ftrs.next().await {
        if let Some(r) = record {
            open_records.push(r);
        }
        if let Some(r ) = active_record_iter.next() {
            ftrs.push(scan_port(r ,Duration::from_millis(conf.conn_timeout),conf.conn_retries));
        }
    }
    let used_time = std::time::SystemTime::now().duration_since(start_time).unwrap();
    println!("[-] Active scan: finished, total found:{}, time used {}.",open_records.len(),if used_time.as_secs() > 60 { format!("{} min {} s",used_time.as_secs()/60,used_time.as_secs()%60)} else { format!("{} s",used_time.as_secs()) });
    for r in open_records {
        result_sender.send(Message::Content(Box::new(r))).unwrap();
    }
    result_sender.send(Message::Finished).unwrap();
}

fn urls_finger(conf:UrlsConfig,result_sender:SyncSender<Message>) {
    if conf.urls.len() == 0 {
        println!("[!] Url scan got nothing input");
        return;
    };
    println!("[-] Url scan: total:{}",conf.urls.len());
    let es = read_excludes(conf.exclude_files);
    for u in conf.urls.iter() {
        if !es.contains(u) {
            if let Some(record) = url_to_passive_record(u) {
                result_sender.send(Message::Content(Box::new(record))).unwrap();
            };
        }
    }
    result_sender.send(Message::Finished).unwrap();
}

fn is_assets(rst_config:&ResultConfig,data:&Data) -> bool {
    for domain in rst_config.it_assets.0.iter() {
        if domain.contains(&data.host) || data.host.contains(domain) {
            return true;
        }
        for c_d in data.cert_domains.iter() {
            if c_d.contains(domain) {
                return true;
            } 
        }
    }
    for ip in rst_config.it_assets.1.iter() {
        if ip.starts_with(&data.ip) || ip.starts_with(&data.host) {
            return true;
        } 
    }
    return false;
}

async fn result_handler(detector:Detector,rst_config:ResultConfig,receiver:Receiver<Message>) {
    let mut results:Vec<Data> = Vec::new();
    let mut notices = Vec::new();
    let mut caches:HashMap<String,NoNeedCheckDataCache> = HashMap::new();  //{"host:port":cache} 最后和results合并
    let mut checked = String::with_capacity(1024*10);      //记录已经check的host:port
    let mut excludes = String::with_capacity(1024*20);     //记录排除的host:port
    for ef in  rst_config.poc_exclude_files.iter() {
        read_csv_to_excludes(&mut excludes,ef);
    };
    let mut ftrs  = FuturesUnordered::new();
    let mut ftrs_num = 0;
    let mut recv_finished = false;
    loop {
        if ftrs_num == rst_config.detect_limit {
            break;
        }
        if recv_finished {
            break;
        }
        if let Ok(m) = receiver.recv() {
            match m {
                Message::Content(mut record) => {
                    //去重处理！///////////////////////////////////////////////////////////////////////////////// 保留title
                    if record.record_type() == Other {
                        notices.push(record);
                    } else { //active passive
                        let mut host_port = record.record().unwrap();
                        let protocol = record.protocol();
                        if protocol == "http" || protocol == "https" {   //有的端口http https都可以访问，所以这里需要加上协议，否则可能跳过一些链接！
                            host_port = format!("{}{}",protocol,host_port)
                        }
                        if excludes.contains(&host_port) {
                            continue;
                        } else {
                            if checked.contains(&host_port) {
                                let title = record.title().trim().to_string();
                                let mut cert_domains = record.cert_domains().unwrap_or_else(||{vec![]});
                                if let Some(cache) = caches.get_mut(&host_port) {
                                    if cache.title != title {
                                        cache.title += &title;
                                    }
                                    for _ in 0..cert_domains.len() {
                                        let domain = cert_domains.pop().unwrap();
                                        if !cache.cert_domains.contains(&domain) {
                                            cache.cert_domains.push(domain);
                                        }
                                    }
                                } else {
                                    caches.insert(host_port,NoNeedCheckDataCache{title,cert_domains});
                                }
                            } else {
                                checked.push_str(&(host_port+" "));
                                ftrs.push(detector.detect(record));
                                ftrs_num += 1;
                            }
                        }
                    }
                },
                Message::Finished => {
                    recv_finished = true;
                    break;
                }
            }
        } else {
            recv_finished = true;
            break;
        }
    }
    while let Some(data) = ftrs.next().await {  //注意了 等待一个future完成，则接收一个record，如果这个record没有push到futures中！，那么实际上futures会比record少，这时futures执行完了，record可能还没发送完，就会出现bug!
        if let Some(mut data) = data {
            if data.level >= rst_config.print_level && data.status_code > 0 {
                println!("[+] Found {}://{}:{} [{}] [{}] {:?}",data.protocol,data.host,data.port,data.status_code,data.title,data.infos);
            }
            data.is_assets = is_assets(&rst_config,&data);
            results.push(data);
        }
        if !recv_finished {
            if let Ok(m) = receiver.recv() {
                match m {
                    Message::Content(mut record) => {
                        if record.record_type() == Other {
                            notices.push(record);
                            ftrs.push(detector.detect(Box::new(OtherRecord::new(OtherRecordInfo::Padding))));
                        } else {
                            let mut host_port = record.record().unwrap();
                            let protocol = record.protocol();
                            if protocol == "http" || protocol == "https" {   //有的端口http https都可以访问，所以这里需要加上协议，否则可能跳过一些链接！
                                host_port = format!("{}{}",protocol,host_port)
                            }
                            if excludes.contains(&host_port) {
                                ftrs.push(detector.detect(Box::new(OtherRecord::new(OtherRecordInfo::Padding))));  //需要push一个future 平衡futures和record的数量
                            } else {
                                if checked.contains(&host_port) {
                                    let title = record.title().trim().to_string();
                                    let mut cert_domains = record.cert_domains().unwrap_or_else(||{vec![]});
                                    if let Some(cache) = caches.get_mut(&host_port) {
                                        if cache.title != title {
                                            cache.title += &title;
                                        }
                                        for _ in 0..cert_domains.len() {
                                            let domain = cert_domains.pop().unwrap();
                                            if !cache.cert_domains.contains(&domain) {
                                                cache.cert_domains.push(domain);
                                            }
                                        }
                                    } else {
                                        caches.insert(host_port,NoNeedCheckDataCache{title,cert_domains});
                                    }
                                    ftrs.push(detector.detect(Box::new(OtherRecord::new(OtherRecordInfo::Padding))));  //需要push一个future 平衡futures和record的数量
                                } else {
                                    checked.push_str(&(host_port+" "));
                                    ftrs.push(detector.detect(record));
                                }
                            }
                        }
                    },
                    Message::Finished => {
                        recv_finished = true;
                    }
                }
            } else {
                recv_finished = true;
            }
        }
    }
    //println!("{:?}",caches);
    for data in results.iter_mut() {
        let host_port = format!("{}:{}",data.host,data.port);
        if let Some(cache) = caches.get_mut(&host_port) {
            if data.title != cache.title {
                data.title += &cache.title;
            }
            for _ in 0..cache.cert_domains.len() {
                let d = cache.cert_domains.pop().unwrap();
                data.cert_domains.push(d);
            }
        }
    }
    
    if notices.len() > 0 {
        let notice_path = &format!("{}_results_notice.txt",rst_config.output_file_name);
        if let Ok(mut f) = fs::OpenOptions::new().create(true).write(true).open(notice_path) {
            for r in notices {
                let info = [r.record().unwrap().as_bytes(),b"\n"].concat();
                f.write(&info).unwrap();
            }
        } else {
            println!("[!] Can not open result notice file {}! notice will be printed to stdout.",notice_path);
            for r in notices {
                println!("{}",r.record().unwrap());
            }
        }
    };
    
    if results.len() > 0 {
        let result_path = &format!("{}_results.csv",rst_config.output_file_name);
        let mut wrt = Writer::from_writer(vec![]);
        wrt.write_record(RST_COLS).unwrap();
        for d in results.iter() {
            if let Err(_) = write_data_to_csv(&mut wrt, d) {
                println!("{:?}",d);
            }
        }
        let data = wrt.into_inner().unwrap();
        let estr = rst_config.output_encode.to_lowercase();
        let rst = if estr != "utf-8" && estr != "utf_8" {
            if let Some(encoding) = encoding_rs::Encoding::for_label(rst_config.output_encode.as_bytes()) {
                let (dec_data,_,_) = encoding_rs::UTF_8.decode(&data);
                let (data,_,_) = encoding.encode(&dec_data);
                data.to_vec()
            } else {
                println!("[!] unsupported encoding type {}",rst_config.output_encode);
                data
            }
        } else {
            data
        };
        if let Ok(mut f) = fs::OpenOptions::new().create(true).write(true).open(result_path) {
            let _ = f.write_all(&rst);
        } else {
            println!("[!] Can not save results to file {}! results will be printed to stdout.",result_path);
            for d in results.iter() {
                println!("{:?}\n",d);
            }
            return;
        }
        println!("[-] Result saved in \"{}\",total {}.",result_path,results.len());
    } else {
        println!("[!] No results found");
    }
}

static  BANNER:&'static str = r"______________________________________________________
  ______     ______     ______   ______     __        
 /\  == \   /\  __ \   /\__  _\ /\  ___\   /\ \       
 \ \  __<   \ \  __ \  \/_/\ \/ \ \  __\   \ \ \____  
  \ \_\ \_\  \ \_\ \_\    \ \_\  \ \_____\  \ \_____\ 
   \/_/ /_/   \/_/\/_/     \/_/   \/_____/   \/_____/ 
_____________________________________Author: h4cnull__
";

fn main() {
    println!("{}",BANNER);
    let start_time = std::time::SystemTime::now();
    let (rst_config,conf) = get_config();
    println!("=> {flag:<width$}{value}",flag="connection timeout(ms):",width=25,value=rst_config.conn_timeout);
    println!("=> {flag:<width$}{value}",flag="poc enabled:",width=25,value=!rst_config.disable_poc);
    println!("=> {flag:<width$}{value}",flag="pocs file:",width=25,value=rst_config.pocs_file);
    println!("=> {flag:<width$}{value}",flag="follow redirect:",width=25,value=rst_config.follow_redirect);
    let rst_con_num = rst_config.per_url_limit as usize * rst_config.detect_limit as usize;
    let max_conections = match &conf {Config::Active(a)=> { if a.async_scan_limit as usize > rst_con_num { a.async_scan_limit as usize } else { rst_con_num } },_=> rst_con_num + 2 };
    println!("=> {flag:<width$}{value}",flag="max connections:",width=25,value=max_conections);
    println!("=> {flag:<width$}{value}",flag="output name:",width=25,value=rst_config.output_file_name);
    let pocs = if rst_config.disable_poc {
        vec![]
    } else {
        let pocs_file = &rst_config.pocs_file;
        let pocs = match fs::read_to_string(pocs_file) {
            Ok(json_str) => {
                match serde_json::from_str::<Pocs>(json_str.trim()) {
                    Ok(pocs) => {
                        pocs.pocs
                    },
                    Err(e) => {
                        println!("[!] Parse POC file {} error: {}",pocs_file,e.to_string());
                        std::process::exit(-1);
                    }
                }
            },
            Err(e) => {
                println!("[!] Read POC file {} error: {:?}",pocs_file,e.kind());
                std::process::exit(-1);
            }
        };
        println!("[-] Total pocs {}",pocs.len());
        pocs
    };
    let detector = Detector::new(&rst_config, pocs);
    //println!("=> ip:port detect limit: {}",rst_config.detect_limit);
    let (result_sender,result_receiver) = mpsc::sync_channel::<Message>(rst_config.detect_limit as usize);
    let mut handlers = Vec::new();
    handlers.push(Some(thread::spawn(move||{
        block_on(result_handler(detector,rst_config, result_receiver));
    })));
    match conf {
        Config::Passive(p) => {
            handlers.push(Some(thread::spawn(move||{
                passive(p,result_sender)}
            )));
        },
        Config::Active(a) => {
            handlers.push(Some(thread::spawn(move||{
                block_on(active(a,result_sender));
            })));
        },
        Config::Urls(u) => {
            handlers.push(Some(thread::spawn(move||{
                urls_finger(u,result_sender);
            })));
        }
    } 
    for h in handlers.iter_mut() {
        h.take().unwrap().join().unwrap();
    }
    let used_time = std::time::SystemTime::now().duration_since(start_time).unwrap();
    println!("[-] Time used {}.",if used_time.as_secs() > 60 { format!("{} min {} s",used_time.as_secs()/60,used_time.as_secs()%60)} else { format!("{} s",used_time.as_secs()) });
}
