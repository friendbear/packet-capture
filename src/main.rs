use std::env;
use pnet::datalink;
#[macro_use]
extern crate log;

mod packets;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        error!("Please specify target interface name");
        std::process::exit(1);
    }

    let interface_name = &args[1];

    let interfaces = datalink::interfaces();
    let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == *interface_name)
            .expect("Failed to get interface");
    
}
