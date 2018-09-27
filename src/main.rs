extern crate actix;
extern crate failure;
extern crate olaf2;
extern crate oauth2;
extern crate toml;

use actix::prelude::*;
use failure::Error;
use oauth2::prelude::SecretNewType;   
use olaf2::*;

use std::env;

fn main() {
	env_logger::init();


	match env::args().nth(1) {
		Some(ref s) if s == "server" => server_main(),
		Some(ref c) if c == "client" => client_main(),
		_ => eprintln!("Usage: olaf2 (client|server)"),
	}
}

fn server_main() {
	let toml = include_str!("proxy_config.toml");
	let config: proxy::Config = toml::from_str(toml).unwrap();
	proxy::run_with(config, |token| {
		let secret = token.secret().to_string();
		println!("Received token: {}", &secret);
		Ok(secret)
	});
}

fn client_main() {
	let secret = client::authenticate::<String>("http://127.0.0.1:8081");
	println!("Secret: {}", secret);
}
