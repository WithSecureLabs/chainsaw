use std::borrow::Cow;

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value as Json};
use tau_engine::{AsValue, Document, Object, Value as Tau};

#[derive(Clone, Deserialize, Serialize)]
pub enum Value {
    Null,
    Bool(bool),
    Float(f64),
    Int(i64),
    UInt(u64),
    String(String),
    Array(Vec<Value>),
    Object(FxHashMap<String, Value>),
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

impl AsValue for Value {
    #[inline]
    fn as_value(&self) -> Tau<'_> {
        match self {
            Self::Null => Tau::Null,
            Self::String(s) => Tau::String(Cow::Borrowed(s)),
            Self::Float(f) => Tau::Float(*f),
            Self::Int(i) => Tau::Int(*i),
            Self::UInt(u) => Tau::UInt(*u),
            Self::Bool(b) => Tau::Bool(*b),
            Self::Object(o) => Tau::Object(o),
            Self::Array(a) => Tau::Array(a),
        }
    }
}

impl Document for Value {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        if let Self::Object(o) = self {
            return Object::find(o, key);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_to_value() {
        let v = Value::from(json!({
            "null": null,
            "bool": true,
            "uint": 1u64,
            "int": -1i64,
            "float": 1.5,
            "string": "s",
            "array": [1],
        }));
        match v {
            Value::Object(o) => {
                assert!(matches!(o.get("null"), Some(Value::Null)));
                assert!(matches!(o.get("bool"), Some(Value::Bool(true))));
                assert!(matches!(o.get("uint"), Some(Value::UInt(1))));
                assert!(matches!(o.get("int"), Some(Value::Int(-1))));
                assert!(matches!(o.get("float"), Some(Value::Float(_))));
                assert!(matches!(o.get("string"), Some(Value::String(_))));
                assert!(matches!(o.get("array"), Some(Value::Array(_))));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn value_to_json() {
        assert_eq!(Json::from(Value::Null), Json::Null);
        assert_eq!(Json::from(Value::Bool(true)), json!(true));
        assert_eq!(Json::from(Value::Float(1.5)), json!(1.5));
        assert_eq!(Json::from(Value::Int(-1)), json!(-1));
        assert_eq!(Json::from(Value::UInt(1)), json!(1));
        assert_eq!(Json::from(Value::String("s".to_string())), json!("s"));
        assert_eq!(Json::from(Value::Array(vec![Value::UInt(1)])), json!([1]));
        let mut o = FxHashMap::default();
        o.insert("k".to_string(), Value::String("v".to_string()));
        assert_eq!(Json::from(Value::Object(o)), json!({"k": "v"}));
    }

    #[test]
    fn value_as_tau() {
        assert!(matches!(Value::Null.as_value(), Tau::Null));
        assert!(matches!(Value::Bool(true).as_value(), Tau::Bool(true)));
        assert!(matches!(Value::Int(-1).as_value(), Tau::Int(-1)));
        assert!(matches!(Value::UInt(1).as_value(), Tau::UInt(1)));
        match Value::Float(1.5).as_value() {
            Tau::Float(f) => assert_eq!(f, 1.5),
            _ => panic!("expected Float"),
        }
        match Value::String("s".to_string()).as_value() {
            Tau::String(s) => assert_eq!(s.as_ref(), "s"),
            _ => panic!("expected String"),
        }
        assert!(matches!(Value::Array(vec![]).as_value(), Tau::Array(_)));
        assert!(matches!(
            Value::Object(FxHashMap::default()).as_value(),
            Tau::Object(_)
        ));
    }

    #[test]
    fn value_supports_find() {
        let v = Value::from(json!({"k": "v"}));
        assert!(v.find("k").is_some());
        assert!(v.find("missing").is_none());
        assert!(Value::Null.find("k").is_none());
    }
}
