use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Serialize,
};
use tau_engine::core::{
    parser::{Expression, Pattern},
    Detection,
};

use crate::file::Kind;

#[derive(Clone, Debug, Deserialize)]
pub struct Aggregate {
    #[serde(deserialize_with = "crate::ext::tau::deserialize_numeric")]
    pub count: Pattern,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Container {
    pub name: String,
    pub format: Format,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub from: String,
    pub to: String,

    pub container: Option<Container>,
    pub visible: bool,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Field")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Field, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut container = None;
                let mut from = None;
                let mut name = None;
                let mut to = None;
                let mut visible = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "name" => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "from" => {
                            if from.is_some() {
                                return Err(de::Error::duplicate_field("from"));
                            }
                            from = Some(map.next_value()?);
                        }
                        "to" => {
                            if to.is_some() {
                                return Err(de::Error::duplicate_field("to"));
                            }
                            to = Some(map.next_value()?);
                        }
                        "container" => {
                            if container.is_some() {
                                return Err(de::Error::duplicate_field("container"));
                            }
                            container = Some(map.next_value()?);
                        }
                        "visible" => {
                            if visible.is_some() {
                                return Err(de::Error::duplicate_field("visible"));
                            }
                            visible = Some(map.next_value()?);
                        }
                        _ => return Err(de::Error::unknown_field(&key, FIELDS)),
                    }
                }
                if name.is_none() && to.is_none() {
                    return Err(de::Error::missing_field("to"));
                }
                let to: String = to.ok_or_else(|| de::Error::missing_field("to"))?;
                let name = name.unwrap_or_else(|| to.clone());
                let from = from.unwrap_or_else(|| to.clone());
                let container = container.unwrap_or_default();
                let visible = visible.unwrap_or_else(|| true);
                Ok(Field {
                    name,
                    to,
                    from,
                    container,
                    visible,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["container", "from", "name", "to", "visible"];
        deserializer.deserialize_struct("Field", FIELDS, FieldVisitor)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Detection(Detection),
    #[serde(deserialize_with = "crate::ext::tau::deserialize_expression")]
    Expression(Expression),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Stable,
    Testing,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Testing => write!(f, "testing"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    #[serde(alias = "title")]
    pub name: String,
    pub group: String,
    pub description: String,
    pub authors: Vec<String>,

    pub kind: Kind,
    pub level: Level,
    pub status: Status,
    pub timestamp: String,

    pub fields: Vec<Field>,

    pub filter: Filter,

    #[serde(default)]
    pub aggregate: Option<Aggregate>,
}

pub fn load(rule: &Path) -> crate::Result<Rule> {
    let mut file = File::open(rule)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let rule: Rule = serde_yaml::from_str(&contents)?;
    Ok(rule)
}
