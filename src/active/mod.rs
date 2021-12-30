use std::net::ToSocketAddrs;
use async_std::io;
use async_std::net::TcpStream;
use std::{
    net::Shutdown,
    time::Duration,
};
use num_bigint::{BigUint,ToBigUint};
use cidr_utils::cidr::{IpCidr,IpCidrIpAddrIterator};
use super::ActiveRecord;

#[derive(Clone)]
pub struct Host {
    pub host:String,
    pub ip:String
}

pub struct TargetIter {
    hosts: Vec<Host>,
    hosts_index: usize,
    hosts_len: usize,
    cidr_iters: Vec<IpCidrIpAddrIterator>,
    cidr_iters_index: usize,
    cidr_iters_len: usize,
    cidrs_backup: Vec<IpCidr>,
    total:BigUint
}

impl TargetIter {
    pub fn new() -> TargetIter {
        TargetIter {
            hosts: vec![],
            hosts_index: 0,
            hosts_len: 0,
            cidr_iters: vec![],
            cidr_iters_index: 0,
            cidr_iters_len: 0,
            cidrs_backup: vec![],
            total:0.to_biguint().unwrap()
        }
    }
    
    pub fn append(&mut self,host:Host) {       //append ip或者域名前 先进行dns解析！
        self.hosts.push(host);
        self.hosts_len += 1;
        self.total += (1 as usize).to_biguint().unwrap();
    }

    pub fn append_cidr(&mut self,cidr:IpCidr) {
        let cidr_backup = cidr.clone();
        self.total += cidr.size();
        self.cidr_iters.push(cidr.iter());
        self.cidrs_backup.push(cidr_backup);
        self.cidr_iters_len += 1;
    }

    pub fn reset(&mut self) {
        self.hosts_index = 0;
        self.cidr_iters_index = 0;
        let mut tmp = Vec::new();
        for cidr in self.cidrs_backup.iter() {
            let cidr = cidr.clone();
            tmp.push(cidr.iter());
        }
        self.cidr_iters_len = tmp.len();
        self.cidr_iters = tmp;
    }
    pub fn total(&self)-> &BigUint {
        &self.total
    }
}

impl Iterator for TargetIter {
    type Item = Host;
    fn next(&mut self) -> Option<Self::Item>{
        if self.hosts_index < self.hosts_len {
            let host = (&self.hosts[self.hosts_index]).clone();
            self.hosts_index += 1;
            return Some(host.clone());
        } else {
            if self.cidr_iters_index < self.cidr_iters_len {
                if let Some(addr) = self.cidr_iters[self.cidr_iters_index].next() {
                    return Some(
                        Host {
                            host: addr.to_string(),
                            ip: addr.to_string()
                        }
                    );
                } else {
                    self.cidr_iters_index += 1;
                    return self.next();
                }
            } else {
                return None;
            }
        }
    }
}

pub struct ActiveRecordIter {
    target_iter: TargetIter,
    ports: Vec<u16>,
    ports_index: usize,
    ports_len: usize
}

impl ActiveRecordIter {
    pub fn new(target_iter:TargetIter,ports:Vec<u16>) ->ActiveRecordIter {
        let ports_len = ports.len();
        ActiveRecordIter {
            target_iter,
            ports,
            ports_index: 0,
            ports_len
        }
    }
}

impl Iterator for ActiveRecordIter {
    type Item = ActiveRecord;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ports_index < self.ports_len {
            let port = self.ports[self.ports_index];
            if let Some(target) = self.target_iter.next() {
                return Some(ActiveRecord {
                    host:target.host,
                    ip:target.ip,
                    port
                });
            } else {
                self.target_iter.reset();
                self.ports_index += 1;
                return self.next();
            }
        } else {
            return None;
        }
    }
}

pub async fn scan_port(record:ActiveRecord,timeout:Duration,tries:u8) -> Option<ActiveRecord> {
    let addr = format!("{}:{}",record.ip,record.port);
    let mut socket_addrs = addr.to_socket_addrs().unwrap();   //record确保ip和port合法
    let socket_addr = socket_addrs.next().unwrap();
    let mut try_num = 0;
    let mut rst: Option<ActiveRecord> = None;
    loop {
        try_num += 1;
        match io::timeout(timeout,async move { TcpStream::connect(socket_addr).await }).await {
            Ok(stream) => {
                stream.shutdown(Shutdown::Both).unwrap_or_else(|_|{});
                rst = Some(record);
                break;
            },
            Err(e) => {
                if try_num > tries {
                    //输出非time out的错误
                    //if e.to_string().contains("future timed out") {
                    if e.to_string().to_lowercase().contains("too many open files") {
                        println!("[!] Active scan error: {} {}",socket_addr.to_string(),e.to_string());
                        //linux下错误中如果包含"too many open files", socket过多，提示减少limit数量，windows下错误信息待测。
                    }
                    break;
                }
            },
        };
    }
    return rst;
}
