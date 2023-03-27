use std::path::Path;
use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs

#[test]
fn search_jq_simple_string() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/evtx").join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root).join("tests/evtx").join("clo_search_qj_simple_string.txt");
    let mut cmd = Command::cargo_bin("chainsaw")?;

    cmd.arg("search").arg("4624").arg(sample_path).arg("-jq");
    cmd.assert()
        .success()
        .stdout( predicate::path::eq_file(sample_expected_output_path).utf8().unwrap());
    
    Ok(())
}

#[test]
fn search_q_jsonl_simple_string()-> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/evtx").join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root).join("tests/evtx").join("clo_search_q_jsonl_simple_string.txt");
    let mut cmd = Command::cargo_bin("chainsaw")?;

    cmd.arg("search").arg("4624").arg(sample_path).arg("-q").arg("--jsonl");
    cmd.assert()
        .success()
        .stdout( predicate::path::eq_file(sample_expected_output_path).utf8().unwrap());
    
    Ok(())
}
#[test]
fn search_q_simple_string()-> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/evtx").join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root).join("tests/evtx").join("clo_search_q_simple_string.txt");
    let mut cmd = Command::cargo_bin("chainsaw")?;

    cmd.arg("search").arg("4624").arg(sample_path).arg("-q");
    cmd.assert()
        .success()
        .stdout( predicate::path::eq_file(sample_expected_output_path).utf8().unwrap());
    
    Ok(())
}

#[test]
fn hunt_r_any_logon()-> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/evtx").join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root).join("tests/evtx").join("clo_hunt_r_any_logon.txt");
    let rule_path = Path::new(root).join("tests/evtx").join("rule-any-logon.yml");
    let mut cmd = Command::cargo_bin("chainsaw")?;

    cmd.arg("hunt").arg(sample_path).arg("-r").arg(rule_path);
    cmd.assert()
        .success()
        .stdout( predicate::path::eq_file(sample_expected_output_path).utf8().unwrap());
    
    Ok(())
}