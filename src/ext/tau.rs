use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasickBuilder, AhoCorasickKind};
use serde::de;
use serde_yaml::Value as Yaml;
use tau_engine::core::parser::{
    parse_identifier, BoolSym, Expression, IdentifierParser, MatchType, ModSym, Pattern, Search,
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

pub fn extract_fields(expression: &Expression) -> HashSet<String> {
    let mut set = HashSet::new();
    match expression {
        Expression::BooleanGroup(_, expressions) => {
            for expression in expressions {
                set.extend(extract_fields(expression));
            }
        }
        Expression::BooleanExpression(left, _, right) => {
            set.extend(extract_fields(left));
            set.extend(extract_fields(right));
        }
        Expression::Cast(s, _) => {
            set.insert(s.to_owned());
        }
        Expression::Field(f) => {
            set.insert(f.to_owned());
        }
        Expression::Match(_, e) => {
            set.extend(extract_fields(e));
        }
        Expression::Matrix(fields, _) => {
            for field in fields {
                set.insert(field.to_owned());
            }
        }
        Expression::Negate(e) => {
            set.extend(extract_fields(e));
        }
        Expression::Nested(field, _) => {
            set.insert(field.to_owned());
        }
        Expression::Search(_, field, _) => {
            set.insert(field.to_owned());
        }
        Expression::Boolean(_)
        | Expression::Float(_)
        | Expression::Identifier(_)
        | Expression::Integer(_)
        | Expression::Null => {}
    }
    set
}

pub fn update_fields(expression: Expression, lookup: &HashMap<String, String>) -> Expression {
    match expression {
        Expression::BooleanGroup(x, expressions) => {
            let expressions = expressions
                .into_iter()
                .map(|e| update_fields(e, lookup))
                .collect();
            Expression::BooleanGroup(x, expressions)
        }
        Expression::BooleanExpression(left, x, right) => Expression::BooleanExpression(
            Box::new(update_fields(*left, lookup)),
            x,
            Box::new(update_fields(*right, lookup)),
        ),
        Expression::Cast(field, x) => {
            let field = lookup.get(&field).expect("could not get field");
            Expression::Cast(field.to_owned(), x)
        }
        Expression::Field(field) => {
            let field = lookup.get(&field).expect("could not get field");
            Expression::Field(field.to_owned())
        }
        Expression::Match(x, e) => Expression::Match(x, Box::new(update_fields(*e, lookup))),
        Expression::Matrix(fields, x) => {
            let fields = fields
                .into_iter()
                .map(|f| lookup.get(&f).expect("could not get field"))
                .cloned()
                .collect();
            Expression::Matrix(fields, x)
        }
        Expression::Negate(e) => Expression::Negate(Box::new(update_fields(*e, lookup))),
        Expression::Nested(field, x) => {
            let field = lookup.get(&field).expect("could not get field");
            Expression::Nested(field.to_owned(), x)
        }
        Expression::Search(x, field, y) => {
            let field = lookup.get(&field).expect("could not get field");
            Expression::Search(x, field.to_owned(), y)
        }
        Expression::Boolean(_)
        | Expression::Float(_)
        | Expression::Identifier(_)
        | Expression::Integer(_)
        | Expression::Null => expression,
    }
}

pub fn parse_field(key: &str) -> Expression {
    if key.starts_with("int(") && key.ends_with(')') {
        let key = key[4..key.len() - 1].to_owned();
        Expression::Cast(key, ModSym::Int)
    } else if key.starts_with("str(") && key.ends_with(')') {
        let key = key[4..key.len() - 1].to_owned();
        Expression::Cast(key, ModSym::Str)
    } else {
        Expression::Field(key.to_owned())
    }
}

pub fn parse_kv(kv: &str) -> crate::Result<Expression> {
    let mut parts = kv.split(": ");
    let key = parts
        .next()
        .ok_or(anyhow::anyhow!("Invalid tau key value pair '{}'", kv))?;
    let value = parts
        .next()
        .ok_or(anyhow::anyhow!("Invalid tau key value pair '{}'", kv))?;
    let mut cast = false;
    let mut not = false;
    let (field, key) = if key.starts_with("int(") && key.ends_with(')') {
        let key = key[4..key.len() - 1].to_owned();
        (Expression::Cast(key.to_owned(), ModSym::Int), key)
    } else if key.starts_with("not(") && key.ends_with(')') {
        not = true;
        let key = key[4..key.len() - 1].to_owned();
        (Expression::Field(key.to_owned()), key)
    } else if key.starts_with("str(") && key.ends_with(')') {
        cast = true;
        let key = key[4..key.len() - 1].to_owned();
        (Expression::Cast(key.to_owned(), ModSym::Str), key)
    } else {
        (Expression::Field(key.to_owned()), key.to_owned())
    };
    // NOTE: This is pinched from tau-engine as it is not exposed, we then slightly tweak it to
    // handle casting in a slightly different way :O
    // FIXME: The tau-engine is not able to cast string expressions, I need to fix this upstream :/
    let identifier = if let Some(v) = value.strip_prefix('!') {
        not = true;
        v.to_owned().into_identifier()?
    } else {
        value.to_owned().into_identifier()?
    };
    // Type enforcement
    match (&field, &identifier.pattern) {
        (Expression::Cast(_, ModSym::Str), Pattern::Equal(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::GreaterThan(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::GreaterThanOrEqual(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::LessThan(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::LessThanOrEqual(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::FEqual(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::FGreaterThan(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::FGreaterThanOrEqual(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::FLessThan(_))
        | (Expression::Cast(_, ModSym::Str), Pattern::FLessThanOrEqual(_))
        | (Expression::Cast(_, ModSym::Int), Pattern::Regex(_))
        | (Expression::Cast(_, ModSym::Int), Pattern::Contains(_))
        | (Expression::Cast(_, ModSym::Int), Pattern::EndsWith(_))
        | (Expression::Cast(_, ModSym::Int), Pattern::Exact(_))
        | (Expression::Cast(_, ModSym::Int), Pattern::StartsWith(_))
        | (Expression::Cast(_, ModSym::Flt), Pattern::Regex(_))
        | (Expression::Cast(_, ModSym::Flt), Pattern::Contains(_))
        | (Expression::Cast(_, ModSym::Flt), Pattern::EndsWith(_))
        | (Expression::Cast(_, ModSym::Flt), Pattern::Exact(_))
        | (Expression::Cast(_, ModSym::Flt), Pattern::StartsWith(_)) => {
            anyhow::bail!("invalid kv pair - {}", kv);
        }
        (_, _) => {}
    }
    let expression = match identifier.pattern {
        Pattern::Equal(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::Equal,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::GreaterThan(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::GreaterThan,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::GreaterThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::GreaterThanOrEqual,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::LessThan(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::LessThan,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::LessThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::LessThanOrEqual,
            Box::new(Expression::Integer(i)),
        ),
        Pattern::FEqual(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::Equal,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FGreaterThan(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::GreaterThan,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FGreaterThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::GreaterThanOrEqual,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FLessThan(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::LessThan,
            Box::new(Expression::Float(i)),
        ),
        Pattern::FLessThanOrEqual(i) => Expression::BooleanExpression(
            Box::new(field),
            BoolSym::LessThanOrEqual,
            Box::new(Expression::Float(i)),
        ),
        Pattern::Any => Expression::Search(Search::Any, key, cast),
        Pattern::Regex(c) => {
            Expression::Search(Search::Regex(c, identifier.ignore_case), key, cast)
        }
        Pattern::Contains(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .kind(Some(AhoCorasickKind::DFA))
                            .build(vec![c.clone()])
                            .expect("could not build dfa"),
                    ),
                    vec![MatchType::Contains(c)],
                    identifier.ignore_case,
                )
            } else {
                Search::Contains(c)
            },
            key,
            cast,
        ),
        Pattern::EndsWith(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .kind(Some(AhoCorasickKind::DFA))
                            .build(vec![c.clone()])
                            .expect("could not build dfa"),
                    ),
                    vec![MatchType::EndsWith(c)],
                    identifier.ignore_case,
                )
            } else {
                Search::EndsWith(c)
            },
            key,
            cast,
        ),
        Pattern::Exact(c) => Expression::Search(
            if !c.is_empty() && identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .kind(Some(AhoCorasickKind::DFA))
                            .build(vec![c.clone()])
                            .expect("could not build dfa"),
                    ),
                    vec![MatchType::Exact(c)],
                    identifier.ignore_case,
                )
            } else {
                Search::Exact(c)
            },
            key,
            cast,
        ),
        Pattern::StartsWith(c) => Expression::Search(
            if identifier.ignore_case {
                Search::AhoCorasick(
                    Box::new(
                        AhoCorasickBuilder::new()
                            .ascii_case_insensitive(true)
                            .kind(Some(AhoCorasickKind::DFA))
                            .build(vec![c.clone()])
                            .expect("could not build dfa"),
                    ),
                    vec![MatchType::StartsWith(c)],
                    identifier.ignore_case,
                )
            } else {
                Search::StartsWith(c)
            },
            key,
            cast,
        ),
    };
    if not {
        return Ok(Expression::Negate(Box::new(expression)));
    }
    Ok(expression)
}
