use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize,
};
use tau_engine::core::{
    optimiser,
    parser::{Expression, ModSym},
};

use crate::file::Kind;
use crate::rule::{Aggregate, Filter, Level, Status};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "format")]
pub enum Format {
    Json,
    Kv {
        delimiter: String,
        separator: String,
        #[serde(default)]
        trim: bool,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct Container {
    pub field: String,
    #[serde(flatten)]
    pub format: Format,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub from: String,
    pub to: String,

    pub cast: Option<ModSym>,
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
                let mut cast = None;
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
                            let field: String = map.next_value()?;
                            match crate::ext::tau::parse_field(&field) {
                                Expression::Cast(key, sym) => {
                                    to = Some(key);
                                    cast = Some(sym);
                                }
                                Expression::Field(key) => to = Some(key),
                                _ => unreachable!(),
                            }
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
                if name.is_none() && from.is_none() && to.is_none() {
                    return Err(de::Error::missing_field("name"));
                }
                if cast.is_some() && container.is_some() {
                    return Err(de::Error::custom(
                        "cast and container are mutually exclusive",
                    ));
                }

                let (name, from, to) = if from.is_none() && to.is_none() {
                    let name: String = name.ok_or_else(|| de::Error::missing_field("name"))?;
                    let from = from.unwrap_or_else(|| name.clone());
                    let to = to.unwrap_or_else(|| name.clone());
                    (name, from, to)
                } else {
                    let to: String = to.ok_or_else(|| de::Error::missing_field("to"))?;
                    let name = name.unwrap_or_else(|| to.clone());
                    let from = from.unwrap_or_else(|| to.clone());
                    (name, from, to)
                };
                let container = container.unwrap_or_default();
                let visible = visible.unwrap_or(true);
                Ok(Field {
                    name,
                    to,
                    from,
                    cast,
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
            optimiser::matrix(expression)
        }),
    };
    Ok(rule)
}
