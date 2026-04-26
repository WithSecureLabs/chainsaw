use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::path::Path;

#[test]
fn search_jq_simple_string() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root)
        .join("tests/evtx")
        .join("clo_search_qj_simple_string.txt");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("search").arg("4624").arg(sample_path).arg("-jq");
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}

#[test]
fn search_q_jsonl_simple_string() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root)
        .join("tests/evtx")
        .join("clo_search_q_jsonl_simple_string.txt");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("search")
        .arg("4624")
        .arg(sample_path)
        .arg("-q")
        .arg("--jsonl");
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}
#[test]
fn search_q_simple_string() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root)
        .join("tests/evtx")
        .join("clo_search_q_simple_string.txt");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("search").arg("4624").arg(sample_path).arg("-q");
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}

#[test]
fn hunt_r_any_logon() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let sample_expected_output_path = Path::new(root)
        .join("tests/evtx")
        .join("clo_hunt_r_any_logon.txt");
    let rule_path = Path::new(root)
        .join("tests/evtx")
        .join("rule-any-logon.yml");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("hunt").arg(sample_path).arg("-r").arg(rule_path);
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}

#[test]
fn analyse_srum_database_table_details() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/srum").join("SRUDB.dat");
    let software_hive_path = Path::new(root).join("tests/srum").join("SOFTWARE");
    let sample_expected_output_path = Path::new(root)
        .join("tests/srum")
        .join("analysis_srum_database_table_details.txt");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("analyse")
        .arg("srum")
        .arg("--software")
        .arg(software_hive_path)
        .arg(sample_path)
        .arg("--stats-only")
        .arg("-q");
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}

// FIXME: This test is not deterministic so just disabling for now...
#[ignore]
#[test]
fn analyse_srum_database_json() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root).join("tests/srum").join("SRUDB.dat");
    let software_hive_path = Path::new(root).join("tests/srum").join("SOFTWARE");
    let sample_expected_output_path = Path::new(root)
        .join("tests/srum")
        .join("analysis_srum_database_json.txt");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("analyse")
        .arg("srum")
        .arg("--software")
        .arg(software_hive_path)
        .arg(sample_path)
        .arg("-q");
    cmd.assert().success().stdout(
        predicate::path::eq_file(sample_expected_output_path)
            .utf8()
            .unwrap(),
    );

    Ok(())
}

#[test]
fn analyse_gaps_clean_sample() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("--no-banner")
        .arg("analyse")
        .arg("gaps")
        .arg(sample_path);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Channels seen"))
        .stdout(predicate::str::contains("Security: 10 records"))
        .stdout(predicate::str::contains("No RecordID gaps detected"))
        .stdout(predicate::str::contains("No suspicious time gaps detected"));

    Ok(())
}

#[test]
fn analyse_gaps_json_output() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("--no-banner")
        .arg("analyse")
        .arg("gaps")
        .arg("--json")
        .arg(sample_path);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"channel\":\"Security\""))
        .stdout(predicate::str::contains("\"records_seen\":10"))
        .stdout(predicate::str::contains("\"gaps\":[]"));

    Ok(())
}

#[test]
fn analyse_gaps_low_threshold_flags_time_gaps() -> Result<(), Box<dyn std::error::Error>> {
    let root = env!("CARGO_MANIFEST_DIR");
    let sample_path = Path::new(root)
        .join("tests/evtx")
        .join("security_sample.evtx");
    let mut cmd = cargo_bin_cmd!("chainsaw");

    cmd.arg("--no-banner")
        .arg("analyse")
        .arg("gaps")
        .arg("--min-time-gap-minutes")
        .arg("0")
        .arg(sample_path);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("time gap(s) exceeding threshold"));

    Ok(())
}
