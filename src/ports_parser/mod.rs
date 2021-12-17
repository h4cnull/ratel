use regex::Regex;
use itertools::Itertools;

pub struct PortsParser {
    num_reg:Regex,
    range_reg:Regex,
}

impl PortsParser {
    pub fn new()-> PortsParser {
        PortsParser { num_reg: Regex::new(r"^\d+$").unwrap(),
                      range_reg: Regex::new(r"^\d+\-\d+$").unwrap(),
        }
    }
    
    pub fn parse_ports_string(&self,ports_str:&str) ->Result<Vec<u16>,&'static str> {
        let mut ports:Vec<u16> = Vec::new();
        let str_split:Vec<&str> = ports_str.split(',').collect();
        for str in str_split {
            if self.num_reg.is_match(str) {
                if let Ok(num) = str.parse::<u16>() {
                    //if !ports.contains(&num) {   //太占用资源了
                    ports.push(num);
                } else {
                    return Err("got a invalid port number");
                }
            } else if self.range_reg.is_match(str) {
                let start_end:Vec<&str> = str.split('-').collect();
                let start = start_end[0].parse::<u16>();
                let end = start_end[1].parse::<u16>();
                if start.is_err() || end.is_err() {
                    return Err("got a invalid port number");
                } else {
                    let mut start = start.unwrap();
                    let end = end.unwrap();
                    if start < end {
                        if start == 0 {
                            start += 1
                        }
                        for i in start..=end {
                            ports.push(i);
                        }
                    } else {
                        return Err("got a invalid port range");
                    }
                }
            } else {
                return Err("got a invalid port format");   
            }
        }
        let ports:Vec<_> = ports.into_iter().unique().collect();
        Ok(ports)
    }
}