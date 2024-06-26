use std::path::Path;
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, io::Error> {
        let contents = fs::read_to_string(path)?;
        let config: Config = match toml::from_str(&contents) {
            Ok(c) => c,
            Err(e) => {
                log::error!("parse config error {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };

        if (config.username.is_empty() && !config.password.is_empty())
            || (!config.username.is_empty() && config.password.is_empty())
        {
            log::error!("username/password invalid");
            return Err(io::ErrorKind::Other.into());
        }

        Ok(config)
    }
}
