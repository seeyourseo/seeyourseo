#![cfg(target_os = "linux")]

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const CHILD_FLAG: &str = "SITE_SANDBOX_RUNTIME_CHILD";
const PROBE_FLAG: &str = "SITE_SANDBOX_LANDLOCK_PROBE";
const OBSCURA_EXEC_FLAG: &str = "SITE_SANDBOX_OBSCURA_EXEC";

#[test]
fn linux_landlock_v1_status_is_fully_enforced() {
    if std::env::var_os(PROBE_FLAG).is_some() {
        use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

        let status = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI::V1))
            .expect("configure Landlock")
            .create()
            .expect("create Landlock ruleset")
            .restrict_self()
            .expect("apply minimal Landlock ruleset");
        println!("minimal Landlock status: {status:?}");
        assert_eq!(
            status.ruleset,
            landlock::RulesetStatus::FullyEnforced,
            "kernel must fully enforce Landlock ABI v1"
        );
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "linux_landlock_v1_status_is_fully_enforced",
            "--nocapture",
        ])
        .env(PROBE_FLAG, "1")
        .output()
        .expect("run Landlock probe child");
    assert!(
        output.status.success(),
        "Landlock probe failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn linux_service_roles_apply_and_keep_processes_confined() {
    const ROLE_FLAG: &str = "SITE_SANDBOX_ROLE_CHILD";

    if let Some(role) = std::env::var_os(ROLE_FLAG).and_then(|value| value.into_string().ok()) {
        let role = match role.as_str() {
            "crawler" => site_sandbox::Service::Crawler,
            "analyzer" => site_sandbox::Service::Analyzer,
            "renderer" => site_sandbox::Service::Renderer,
            "obscura" => {
                site_sandbox::Service::Obscura(std::env::current_exe().expect("test executable"))
            }
            _ => panic!("unknown role {role}"),
        };
        site_sandbox::apply(role.clone()).expect("apply role sandbox");
        assert!(fs::read("outside-secret.txt").is_err());
        let temp_dir = PathBuf::from(std::env::var_os("TMPDIR").expect("test TMPDIR"));
        assert_eq!(
            fs::write(temp_dir.join("scratch.txt"), b"private scratch").is_ok(),
            matches!(role_name(&role), "renderer" | "obscura")
        );
        assert!(Command::new("/bin/true").status().is_err());
        return;
    }

    for role in ["crawler", "analyzer", "renderer", "obscura"] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "site-sandbox-{role}-{}-{nonce}",
            std::process::id()
        ));
        let scratch = temp.join("private-tmp");
        fs::create_dir_all(&scratch).expect("create role test directories");
        fs::write(
            temp.join("outside-secret.txt"),
            b"must stay outside the sandbox\n",
        )
        .expect("create protected file");

        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "linux_service_roles_apply_and_keep_processes_confined",
                "--nocapture",
            ])
            .current_dir(&temp)
            .env(ROLE_FLAG, role)
            .env("HOME", &temp)
            .env("TMPDIR", &scratch)
            .output()
            .expect("run service-role child test");

        let _ = fs::remove_dir_all(&temp);
        assert!(
            output.status.success(),
            "{role} sandbox child failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn role_name(service: &site_sandbox::Service) -> &'static str {
    match service {
        site_sandbox::Service::Website => "website",
        site_sandbox::Service::Crawler => "crawler",
        site_sandbox::Service::Analyzer => "analyzer",
        site_sandbox::Service::Renderer => "renderer",
        site_sandbox::Service::Obscura(_) => "obscura",
    }
}

#[test]
fn linux_website_policy_confines_files_and_child_exec() {
    if std::env::var_os(CHILD_FLAG).is_some() {
        site_sandbox::apply(site_sandbox::Service::Website).expect("apply website sandbox");

        let allowed = PathBuf::from("data/scan-analytics.jsonl");
        fs::write(&allowed, b"sandbox-write-check\n").expect("write allowed log file");
        assert_eq!(
            fs::read(&allowed).expect("read allowed log file"),
            b"sandbox-write-check\n"
        );
        assert!(fs::read("outside-secret.txt").is_err());
        assert!(fs::write("outside-created.txt", b"blocked").is_err());
        assert!(Command::new("/bin/true").status().is_err());
        return;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let temp = std::env::temp_dir().join(format!(
        "site-sandbox-runtime-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&temp).expect("create test directory");
    fs::write(
        temp.join("outside-secret.txt"),
        b"must stay outside the sandbox\n",
    )
    .expect("create protected file");

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "linux_website_policy_confines_files_and_child_exec",
            "--nocapture",
        ])
        .current_dir(&temp)
        .env(CHILD_FLAG, "1")
        .env("HOME", &temp)
        .env("SCAN_ANALYTICS_PATH", "data/scan-analytics.jsonl")
        .env("VISITOR_LOG_PATH", "data/visitor-access.jsonl")
        .output()
        .expect("run sandboxed child test");

    let _ = fs::remove_dir_all(&temp);
    assert!(
        output.status.success(),
        "sandbox child failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn linux_obscura_fd_exec_starts_the_browser_inside_its_sandbox() {
    match std::env::var(OBSCURA_EXEC_FLAG).as_deref() {
        Ok("before_exec") => {
            let executable = std::env::current_exe().expect("test executable");
            unsafe { std::env::set_var(OBSCURA_EXEC_FLAG, "after_exec") };
            let error = site_sandbox::exec_obscura(
                &executable,
                &[
                    "--exact".into(),
                    "linux_obscura_fd_exec_starts_the_browser_inside_its_sandbox".into(),
                    "--nocapture".into(),
                ],
            );
            panic!("execveat of the allowed browser image failed: {error}");
        }
        Ok("after_exec") => {
            assert!(fs::read("outside-secret.txt").is_err());
            let scratch = PathBuf::from(std::env::var_os("TMPDIR").expect("test TMPDIR"));
            fs::write(scratch.join("browser-scratch.txt"), b"private").expect("write scratch");
            assert!(Command::new("/bin/true").status().is_err());
            return;
        }
        _ => {}
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let temp = std::env::temp_dir().join(format!(
        "site-sandbox-obscura-exec-{}-{nonce}",
        std::process::id()
    ));
    let scratch = temp.join("private-tmp");
    fs::create_dir_all(&scratch).expect("create private test directories");
    fs::write(temp.join("outside-secret.txt"), b"private").expect("create protected file");

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "linux_obscura_fd_exec_starts_the_browser_inside_its_sandbox",
            "--nocapture",
        ])
        .current_dir(&temp)
        .env(OBSCURA_EXEC_FLAG, "before_exec")
        .env("HOME", &temp)
        .env("TMPDIR", &scratch)
        .output()
        .expect("run Obscura executable-FD child");

    let _ = fs::remove_dir_all(&temp);
    assert!(
        output.status.success(),
        "Obscura executable-FD child failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
