use std::path::Path;

use regex::Regex;
use serde_yaml::Value as Yaml;

use chainsaw::convert::sigma;

mod common;

macro_rules! convert_sigma {
    ($rule:expr) => {
        paste::item! {
            #[test]
            fn [< solve_ $rule >] () {
                let rule = format!("sigma_{}.yml", $rule);
                let root = env!("CARGO_MANIFEST_DIR");
                let path = Path::new(root).join("tests/rules").join(&rule);
                let rules = sigma::load(&path).unwrap();

                let contents = common::load_file("tests/output", &rule).unwrap();
                let regex = Regex::new(r"---\s*\n").expect("invalid regex");
                let yaml: Vec<Yaml> = regex
                    .split(&contents)
                    .filter_map(|y| {
                        if !y.is_empty() {
                            Some(serde_yaml::from_str::<Yaml>(y).unwrap())
                        } else {
                            None
                        }
                    })
                    .collect();
                println!("{}", yaml.len());

                for (y, r) in yaml.iter().zip(rules.iter()) {
                    assert_eq!(y, r);
                }

            }
        }
    };
}

convert_sigma!("simple");
convert_sigma!("collection");
