// #![feature(uniform_paths)]

use abscissa::{impl_global_config, logging, CanonicalPathBuf, GlobalConfig};
use olaf2::*;

fn main() {
    // simulate_client("127.0.0.1:8080".parse().unwrap());
}


impl_global_config!(server::Config, SERVER_CONFIG);

fn server_main() {
	let config = logging::LoggingConfig::verbose();
	logging::init(config).expect("failed to start logging");

	// Find the canonical filesystem path of the configuration
	// let config_path = CanonicalPathBuf::new("/home/sam/work/olaf2/server_config.toml").unwrap();
	let toml = include_str!("server_config.toml");
	let config = Config::load_toml(toml).expect("invalid config");
	Config::set_global(config);
	// Load `Config` from the given TOML file or exit
	// Config::set_from_toml_file_or_exit(&config_path);
}