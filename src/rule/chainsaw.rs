use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Serialize,
};
use tau_engine::core::{
    optimiser,
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
    pub field: String,
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
                let visible = visible.unwrap_or(true);
                Ok(Field {
                    name,
                    to,
                    from,
                    container,
                    visible,
                })
            }
        }

        const FIELDS: &[&str] = &["container", "from", "name", "to", "visible"];
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
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

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "info" => Self::Info,
            _ => anyhow::bail!("unknown level, must be: critical, high, medium, low or info"),
        };
        Ok(v)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Stable,
    Experimental,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Experimental => write!(f, "experimental"),
        }
    }
}

impl FromStr for Status {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "stable" => Self::Stable,
            "experimental" => Self::Experimental,
            _ => anyhow::bail!("unknown status, must be: stable or experimental"),
        };
        Ok(v)
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

    let mut rule: Rule = serde_yaml::from_str(&contents)?;
    rule.filter = match rule.filter {
        Filter::Detection(mut detection) => {
            detection.expression =
                optimiser::coalesce(detection.expression, &detection.identifiers);
            detection.identifiers.clear();
            detection.expression = optimiser::shake(detection.expression);
            detection.expression = optimiser::rewrite(detection.expression);
            detection.expression = optimiser::matrix(detection.expression);
            Filter::Detection(detection)
        }
        Filter::Expression(expression) => Filter::Expression({
            let expression = optimiser::shake(expression);
            let expression = optimiser::rewrite(expression);
            let expression = optimiser::matrix(expression);
            expression
        }),
    };
    Ok(rule)
}
