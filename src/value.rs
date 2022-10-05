use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Number, Value as Json};

#[derive(Deserialize, Serialize)]
pub enum Value {
    Null,
    Bool(bool),
    Float(f64),
    Int(i64),
    UInt(u64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl From<Json> for Value {
    fn from(json: Json) -> Self {
        match json {
            Json::Null => Self::Null,
            Json::Bool(b) => Self::Bool(b),
            Json::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Self::UInt(u)
                } else if let Some(i) = n.as_i64() {
                    Self::Int(i)
                } else if let Some(f) = n.as_f64() {
                    Self::Float(f)
                } else {
                    unreachable!()
                }
            }
            Json::String(s) => Self::String(s),
            Json::Array(a) => Self::Array(a.into_iter().map(|v| v.into()).collect()),
            Json::Object(o) => Self::Object(o.into_iter().map(|(k, v)| (k, v.into())).collect()),
        }
    }
}

impl From<Value> for Json {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(b),
            Value::Float(n) => {
                Self::Number(Number::from_f64(n).expect("could not return to float"))
            }
            Value::Int(n) => Self::Number(Number::from(n)),
            Value::UInt(n) => Self::Number(Number::from(n)),
            Value::String(s) => Self::String(s),
            Value::Array(a) => Self::Array(a.into_iter().map(|v| v.into()).collect()),
            Value::Object(o) => Self::Object(o.into_iter().map(|(k, v)| (k, v.into())).collect()),
        }
    }
}
