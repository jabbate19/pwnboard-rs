//! HTTP Bindings for Pwnboard!
//! 
use reqwest::{Client, Response};
use serde_json::{json, value::Value};
use std::error::Error;

/// Struct for Pwnboard client
/// 
/// Allows for communicationi between application and API route
/// 
/// # Examples
/// ```
/// use pwnboard_rs::Pwnboard
/// 
/// fn main() {
///     let pwn = Pwnboard::new("https://pwnboard.win").expect("Failed to create client");
/// }
/// ```
pub struct Pwnboard {
    pub uri: String,
    client: Client,
}

/// Defines Log Level for Log route
#[derive(Debug)]
pub enum LogLevel {
    Loot,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Value {
    fn from(level: LogLevel) -> Value {
        format!("{:?}", level).to_lowercase().into()
    }
}

impl Pwnboard {
    /// Creates new Pwnboard client pointing to given URI
    pub fn new(uri: &str) -> Result<Pwnboard, Box<dyn Error>> {
        let client = Client::new();
        let uri = String::from(uri);
        let last = uri
            .chars()
            .last()
            .ok_or("Unable to check URI last character. Is it blank?")?;
        if last == '/' {
            Err("Invalid URI - Please do not provide trailing slash")?
        } else {
            Ok(Pwnboard { uri, client })
        }
    }

    /// Indicates access to a box via given application
    pub async fn boxaccess(
        &self,
        ip: &str,
        application: &str,
        ips: Option<&[&str]>,
        access_type: Option<&str>,
        message: Option<&str>,
    ) -> Result<Response, Box<dyn Error>> {
        let mut output_json = json!({
            "ip": ip,
            "application": application,
        });
        if let Some(ip_val) = ips {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("ips".to_owned(), ip_val.into());
        }
        if let Some(access_val) = access_type {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("access_type".to_owned(), access_val.into());
        }
        if let Some(message_val) = message {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("message".to_owned(), message_val.into());
        }
        Ok(self
            .client
            .post(&format!("{}/pwn/boxaccess", self.uri))
            .json(&output_json)
            .send()
            .await?)
    }

    /// Send credentials for box up to Pwnboard
    pub async fn credential(
        &self,
        ip: &str,
        service: &str,
        message: Option<&str>,
        username: Option<&str>,
        password: &str,
    ) -> Result<Response, Box<dyn Error>> {
        let mut output_json = json!({
            "ip": ip,
            "service": service,
            "password": password,
        });
        if let Some(message_val) = message {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("message".to_owned(), message_val.into());
        }
        if let Some(username_val) = username {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("username".to_owned(), username_val.into());
        }
        Ok(self
            .client
            .post(&format!("{}/pwn/credential", self.uri))
            .json(&output_json)
            .send()
            .await?)
    }

    /// Send log to pwnboard for given service
    pub async fn log(
        &self,
        ip: &str,
        message: &str,
        service: &str,
        level: Option<LogLevel>,
    ) -> Result<Response, Box<dyn Error>> {
        let mut output_json = json!({
            "ip": ip,
            "message": message,
            "service": service,

        });
        if let Some(level_val) = level {
            output_json
                .as_object_mut()
                .ok_or("Error in Creating JSON")?
                .insert("level".to_owned(), level_val.into());
        }
        Ok(self
            .client
            .post(&format!("{}/pwn/log", self.uri))
            .json(&output_json)
            .send()
            .await?)
    }
}
