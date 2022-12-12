use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, bail};
use lazy_static::lazy_static;
lazy_static! {
    pub static ref RANDOM_ADDR: SocketAddr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    pub static ref LOCAL_DNS_SERVER: SocketAddr = "127.0.0.1:53".parse::<SocketAddr>().unwrap();
}
use socket2::{Domain, Socket, Type};
use tokio::net::UdpSocket;
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use trust_dns_resolver::system_conf::read_system_conf;

fn create_udp_socket(addr: &SocketAddr) -> anyhow::Result<UdpSocket> {
    let socket = match addr {
        SocketAddr::V4(..) => Socket::new(Domain::IPV4, Type::DGRAM, None),
        SocketAddr::V6(..) => Socket::new(Domain::IPV6, Type::DGRAM, None),
    }?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.clone().into())?;
    let s = UdpSocket::from_std(socket.into())?;
    Ok(s)
}

pub struct DnsClient {
    servers: Vec<SocketAddr>,
    map: HashMap<String, Vec<IpAddr>>,
}

impl DnsClient {
    pub fn new_with_default_resolver() -> anyhow::Result<Self> {
        let conf = read_system_conf()?;
        let servers = conf.0.name_servers();
        let mut inner_servers = Vec::with_capacity(servers.len());
        for server in servers {
            inner_servers.push(server.socket_addr.clone())
        }
        let hosts = DnsClient::load_hosts()?;
        let s = Self {
            servers: inner_servers,
            map: hosts,
        };
        Ok(s)
    }
    fn load_hosts() -> anyhow::Result<HashMap<String, Vec<IpAddr>>> {
        let res = fs::read("/etc/hosts")?;
        let content = String::from_utf8(res).map_err(|_| anyhow!("decode hosts failed"))?;
        let lines = content.split("\n").collect::<Vec<&str>>();
        let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in lines {
            let span = line.split_whitespace().collect::<Vec<&str>>();
            if let Some(x) = span.get(0) {
                let addr = match x.parse::<IpAddr>() {
                    Ok(x) => x,
                    _ => continue,
                };
                let domain_names = &span[1..];
                for s in domain_names {
                    if let Some(inner) = map.get_mut(*s) {
                        inner.push(addr.clone())
                    } else {
                        map.insert(s.to_string(), vec![addr]);
                    }
                }
            }
        }
        Ok(map)
    }
    async fn query(&self, host: String, server: &SocketAddr) -> anyhow::Result<Vec<IpAddr>> {
        let socket = create_udp_socket(&RANDOM_ADDR)?;
        let query = self.new_query(host.clone(), RecordType::A)?;
        let message = query
            .to_vec()
            .map_err(|err| anyhow!("create {} query message failed {}", host, err))?;
        match socket.send_to(&*message, server).await {
            Ok(_x) => {
                let mut buf = [0; 512];
                match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await
                {
                    Ok(x) => match x {
                        Ok((n, _addr)) => {
                            let message = match Message::from_vec(&buf[..n]) {
                                Ok(x) => x,
                                Err(err) => bail!("parse udp response failed {}", err),
                            };
                            let code = message.response_code();
                            if code != ResponseCode::NoError {
                                bail!("response error {}", code);
                            };
                            let mut ips = vec![];
                            for x in message.answers() {
                                if let Some(d) = x.data() {
                                    match d {
                                        RData::A(x) => ips.push(IpAddr::V4(x.clone())),
                                        RData::AAAA(x) => ips.push(IpAddr::V6(x.clone())),
                                        _ => continue,
                                    }
                                }
                            }
                            Ok(ips)
                        }
                        Err(err) => {
                            bail!("socket recv_from return error {}", err)
                        }
                    },
                    Err(_err) => {
                        bail!("receivefrom dns server timeout")
                    }
                }
            }
            Err(err) => {
                bail!("send request to {} failed with error {}", server, err)
            }
        }
    }
    pub async fn lookup(&self, host: String) -> anyhow::Result<Vec<IpAddr>> {
        if let Some(x) = self.map.get(&host) {
            return Ok(x.clone());
        }
        // 先用第一个
        // 后面可以并发请求，用最快的
        let addr = self
            .servers
            .get(0)
            .expect("no dns server found in /etc/resolv.conf");
        self.query(host, addr).await
    }
    pub fn new_query(&self, host: String, ty: RecordType) -> anyhow::Result<Message> {
        let mut name = host.to_string();
        name.push('.');
        let name = Name::from_str(&*name)?;
        let mut msg = Message::new();
        msg.add_query(Query::query(name, ty));
        let id = rand::random();
        msg.set_id(id);
        msg.set_recursion_desired(true);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        Ok(msg)
    }
}

#[cfg(test)]
#[tokio::test]
async fn test_load_hosts() {
    let res = DnsClient::load_hosts().unwrap();
    println!("{:?}", res);
}
