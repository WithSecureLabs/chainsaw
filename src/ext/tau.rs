use aho_corasick::AhoCorasickBuilder;
use serde::de;
use serde_yaml::Value as Yaml;
use tau_engine::core::parser::{
    parse_identifier, BoolSym, Expression, IdentifierParser, MatchType, Pattern, Search,
};

pub fn deserialize_expression<'de, D>(deserializer: D) -> Result<Expression, D::Error>
where
    D: de::Deserializer<'de>,
{
    let yaml: Yaml = de::Deserialize::deserialize(deserializer)?;
    parse_identifier(&yaml).map_err(de::Error::custom)
}

pub fn deserialize_numeric<'de, D>(deserializer: D) -> Result<Pattern, D::Error>
where
    D: de::Deserializer<'de>,
{
    let string: String = de::Deserialize::deserialize(deserializer)?;
    if let Ok(i) = str::parse::<i64>(&string) {
        return Ok(Pattern::Equal(i));
    }
    let identifier = string.into_identifier().map_err(de::Error::custom)?;
    match &identifier.pattern {
        &Pattern::Equal(_)
        | &Pattern::GreaterThan(_)
        | &Pattern::GreaterThanOrEqual(_)
        | &Pattern::LessThan(_)
        | &Pattern::LessThanOrEqual(_) => {}
        _ => return Err(de::Error::custom("only numeric expressions are allowed")),
    }
    Ok(identifier.pattern)
}

pub fn parse_kv(kv: &str) -> crate::Result<Expression> {
    let mut parts = kv.split(": ");
    let key = parts.next().expect("invalid tau key value pair");
    let value = parts.next().expect("invalid tau key value pair");
    // NOTE: This is pinched from tau-engine as it is not exposed.
    let identifier = value.to_owned().into_identifier()?;
    let expression = match identifier.pattern {
        Pattern::Equal(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::Equal,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::GreaterThan(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::GreaterThan,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::GreaterThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::GreaterThanOrEqual,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::LessThan(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::LessThan,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::LessThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::LessThanOrEqual,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::FEqual(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::Equal,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FGreaterThan(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::GreaterThan,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FGreaterThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::GreaterThanOrEqual,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FLessThan(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::LessThan,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FLessThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(Expression::Field(key.to_owned())),
            BoolSym::LessThanOrEqual,
            Box::new(Expression::Float(i)),
        ),
        Pattern::Any => Expression::Search(Search::Any, key.to_owned()),
        Pattern::Regex(c) => Expression::Search(Search::Regex(c), key.to_owned()),
        Pattern::Contains(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .dfa(true)
                            .build(vec![c.clone()]),
                    ),
                    vec![MatchType::Contains(c)],
                )
            } else {
                Search::Contains(c)
            },
            key.to_owned(),
        ),
        Pattern::EndsWith(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .dfa(true)
                            .build(vec![c.clone()]),
                    ),
                    vec![MatchType::EndsWith(c)],
                )
            } else {
                Search::EndsWith(c)
            },
            key.to_owned(),
        ),
        Pattern::Exact(c) => Expression::Search(
            if !c.is_empty() && identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .dfa(true)
                            .build(vec![c.clone()]),
                    ),
                    vec![MatchType::Exact(c)],
                )
            } else {
                Search::Exact(c)
            },
            key.to_owned(),
        ),
        Pattern::StartsWith(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .dfa(true)
                            .build(vec![c.clone()]),
                    ),
                    vec![MatchType::StartsWith(c)],
                )
            } else {
                Search::StartsWith(c)
            },
            key.to_owned(),
        ),
    };
    Ok(expression)
}
