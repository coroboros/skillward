//! SARIF 2.1.0 in and out.
//!
//! Most bundled scanner plans emit SARIF, so one generic reader normalizes those
//! into [`Finding`]s. The writer goes the other way for `--format sarif`, emitting
//! one run per contributing tool so GitHub code scanning and other SARIF consumers
//! see each scanner's native results.

use serde::{Deserialize, Deserializer};
use serde_json::json;

use crate::finding::{Finding, Region, RuleClass, Severity};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Parse a tool's SARIF output into normalized findings, stamping `tool` as the
/// source id. Unrecognized fields are ignored; a malformed document yields an
/// error so the adapter can record a tool-error rather than silently drop results.
pub fn parse(tool: &str, sarif: &str, scan_root: &str) -> Result<Vec<Finding>, String> {
    let doc: SarifDoc = serde_json::from_str(sarif).map_err(|e| e.to_string())?;
    let mut findings = Vec::new();
    for run in doc.runs {
        // Index rule metadata by id: the numeric security-severity (CVSS promotion) and
        // the categorical defaultConfiguration.level (the effective level when a result
        // omits its own — SARIF 2.1.0 §3.27.10).
        let mut scores: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut rule_levels: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for r in run.tool.driver.rules {
            let SarifRule {
                id,
                properties,
                default_configuration,
            } = r;
            if let Some(score) = properties.security_severity {
                scores.insert(id.clone(), score);
            }
            if let Some(level) = default_configuration.level {
                rule_levels.insert(id, level);
            }
        }

        for result in run.results {
            // SARIF 2.1.0 kinds: only `pass`/`notApplicable`/`informational` are clean
            // assertions and get dropped. `fail`, `open` (detected, needs triage), `review`
            // (needs human judgment), and an absent kind (default `fail`) are detections a
            // vetting tool must surface. Suppressions are deliberately NOT honored either:
            // this SARIF is produced from UNTRUSTED skill content, so an in-tree suppression
            // (`.gitleaksignore`, `# nosemgrep`, `gitleaks:allow`) is attacker-controlled —
            // a malicious skill could hide its own secret or injection.
            if result
                .kind
                .as_deref()
                .is_some_and(|k| matches!(k, "pass" | "notApplicable" | "informational"))
            {
                continue;
            }
            let rule_id = result.rule_id.unwrap_or_default();
            // Effective level: the result's own, else the rule's defaultConfiguration
            // level, else SARIF's "warning" default — so a rule that declares its level
            // once and omits it per-result is not silently demoted to Medium.
            let level = result
                .level
                .as_deref()
                .or_else(|| rule_levels.get(&rule_id).map(String::as_str))
                .unwrap_or("warning");
            let mut severity = Severity::from_sarif_level(level);
            if let Some(score) = scores.get(&rule_id)
                && let Some(promoted) = Severity::from_security_severity(score)
            {
                severity = severity.max(promoted);
            }

            let message = result.message.text;
            let class = RuleClass::classify(tool, &rule_id, &message);

            let location = result.locations.into_iter().next();
            let (file, region) = location
                .and_then(|l| l.physical_location)
                .map(|p| {
                    let file = p
                        .artifact_location
                        .and_then(|a| a.uri)
                        .map(|u| normalize_uri(&u, scan_root));
                    let region = p.region.map(Into::into).unwrap_or_default();
                    (file, region)
                })
                .unwrap_or((None, Region::default()));

            findings.push(Finding {
                tool: tool.to_owned(),
                rule_id,
                message,
                severity,
                class,
                file,
                region,
            });
        }
    }
    Ok(findings)
}

/// Strip the sandbox scan-root prefix (the `/scan` mount in Docker, or the absolute
/// skill dir in host mode) and a leading `./` so a finding's path is relative to the
/// scanned skill root, whatever the tool reported it against.
pub(crate) fn normalize_uri(uri: &str, scan_root: &str) -> String {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    // Strip the scan root only as a whole path component, so a sibling like
    // `/scanner/x` is never mistaken for a child of `/scan`.
    let (path, stripped_root) = match path.strip_prefix(scan_root) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => (rest, true),
        _ => (path, false),
    };
    let path = path.trim_start_matches('/');
    // Docker-only fallback: when the mount root is literally `/scan`, a tool may report
    // the bare segment `scan/...` (no leading slash) so the root strip above misses.
    // Gate it on the actual mount — in host mode the scan root is the absolute skill
    // dir, never `/scan`, so a skill's own top-level `scan/` dir is left intact.
    let path = if !stripped_root && scan_root == crate::sandbox::SCAN_MOUNT {
        path.strip_prefix("scan/").unwrap_or(path)
    } else {
        path
    };
    path.strip_prefix("./").unwrap_or(path).to_owned()
}

/// Render findings as SARIF 2.1.0 — one run per contributing tool, preserving each
/// scanner's native results. Serializing owned plain values is infallible.
pub fn render(findings: &[Finding]) -> String {
    let mut tools: Vec<&str> = findings.iter().map(|f| f.tool.as_str()).collect();
    tools.sort_unstable();
    tools.dedup();

    let runs: Vec<serde_json::Value> = tools
        .into_iter()
        .map(|tool| {
            let results: Vec<serde_json::Value> = findings
                .iter()
                .filter(|f| f.tool == tool)
                .map(result_json)
                .collect();
            json!({
                "tool": { "driver": { "name": tool } },
                "results": results,
            })
        })
        .collect();

    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned())
}

fn result_json(f: &Finding) -> serde_json::Value {
    let mut result = json!({
        "ruleId": f.rule_id,
        "level": sarif_level(f.severity),
        "message": { "text": f.message },
        "properties": {
            "skillward-class": f.class.label(),
            "skillward-severity": f.severity.label(),
        },
    });
    if let Some(file) = &f.file {
        let mut physical = json!({ "artifactLocation": { "uri": file } });
        if !f.region.is_empty() {
            let mut region = serde_json::Map::new();
            if let Some(v) = f.region.start_line {
                region.insert("startLine".into(), v.into());
            }
            if let Some(v) = f.region.end_line {
                region.insert("endLine".into(), v.into());
            }
            if let Some(v) = f.region.start_column {
                region.insert("startColumn".into(), v.into());
            }
            if let Some(v) = f.region.end_column {
                region.insert("endColumn".into(), v.into());
            }
            physical["region"] = serde_json::Value::Object(region);
        }
        result["locations"] = json!([{ "physicalLocation": physical }]);
    }
    result
}

/// Map the unified scale back to a SARIF level. Critical has no SARIF peer, so it
/// shares `error` with High; the precise severity rides in `properties`.
const fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[derive(Deserialize, Default)]
struct SarifDoc {
    #[serde(default)]
    runs: Vec<SarifRun>,
}

#[derive(Deserialize, Default)]
struct SarifRun {
    #[serde(default)]
    tool: SarifTool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Deserialize, Default)]
struct SarifTool {
    #[serde(default)]
    driver: SarifDriver,
}

#[derive(Deserialize, Default)]
struct SarifDriver {
    #[serde(default)]
    rules: Vec<SarifRule>,
}

#[derive(Deserialize, Default)]
struct SarifRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    properties: SarifRuleProps,
    #[serde(default, rename = "defaultConfiguration")]
    default_configuration: SarifRuleConfig,
}

#[derive(Deserialize, Default)]
struct SarifRuleProps {
    #[serde(
        default,
        rename = "security-severity",
        deserialize_with = "optional_string_or_number"
    )]
    security_severity: Option<String>,
}

fn optional_string_or_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(value)) => Some(value),
        Some(serde_json::Value::Number(value)) => Some(value.to_string()),
        _ => None,
    })
}

/// A rule's `defaultConfiguration` — the level applied when a result omits its own.
#[derive(Deserialize, Default)]
struct SarifRuleConfig {
    #[serde(default)]
    level: Option<String>,
}

#[derive(Deserialize, Default)]
struct SarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: SarifMessage,
    #[serde(default)]
    locations: Vec<SarifLocation>,
}

#[derive(Deserialize, Default)]
struct SarifMessage {
    #[serde(default)]
    text: String,
}

#[derive(Deserialize, Default)]
struct SarifLocation {
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<SarifPhysical>,
}

#[derive(Deserialize, Default)]
struct SarifPhysical {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: Option<SarifArtifact>,
    #[serde(default)]
    region: Option<SarifRegion>,
}

#[derive(Deserialize, Default)]
struct SarifArtifact {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize, Default)]
struct SarifRegion {
    #[serde(default, rename = "startLine")]
    start_line: Option<u32>,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    #[serde(default, rename = "startColumn")]
    start_column: Option<u32>,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
}

impl From<SarifRegion> for Region {
    fn from(r: SarifRegion) -> Self {
        Self {
            start_line: r.start_line,
            end_line: r.end_line,
            start_column: r.start_column,
            end_column: r.end_column,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const GITLEAKS_SARIF: &str = r#"{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": {
          "name": "gitleaks",
          "rules": [{ "id": "aws-access-token", "properties": { "security-severity": "9.5" } }]
        }},
        "results": [{
          "ruleId": "aws-access-token",
          "level": "error",
          "message": { "text": "AWS Access Token detected" },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "/scan/config.yaml" },
            "region": { "startLine": 12, "startColumn": 3 }
          }}]
        }]
      }]
    }"#;

    #[test]
    fn parses_results_and_promotes_via_security_severity() {
        let findings = parse("gitleaks", GITLEAKS_SARIF, "/scan").unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, "gitleaks");
        assert_eq!(f.rule_id, "aws-access-token");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.class, RuleClass::Secret);
        assert_eq!(f.file.as_deref(), Some("config.yaml"));
        assert_eq!(f.region.start_line, Some(12));
    }

    #[test]
    fn low_security_severity_never_demotes_an_error() {
        let sarif = r#"{"runs":[{"tool":{"driver":{
            "name":"t","rules":[{"id":"r","properties":{"security-severity":"2.0"}}]}},
            "results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}"#;
        let findings = parse("t", sarif, "/scan").unwrap();
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "a low security-severity must not demote an error-level finding"
        );
    }

    #[test]
    fn severity_and_sarif_level_mappings_stay_consistent() {
        assert_eq!(sarif_level(Severity::Low), "note");
        assert_eq!(Severity::from_sarif_level("note"), Severity::Low);
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(Severity::from_sarif_level("warning"), Severity::Medium);
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(Severity::from_sarif_level("error"), Severity::High);
    }

    #[test]
    fn missing_level_defaults_to_warning() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"t"}},
            "results":[{"ruleId":"r","message":{"text":"m"}}]}]}"#;
        let findings = parse("t", sarif, "/scan").unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn warning_level_promoted_to_critical_by_security_severity() {
        let sarif = r#"{"runs":[{"tool":{"driver":{
            "name":"t","rules":[{"id":"r","properties":{"security-severity":"9.8"}}]}},
            "results":[{"ruleId":"r","level":"warning","message":{"text":"m"}}]}]}"#;
        let findings = parse("t", sarif, "/scan").unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn numeric_security_severity_is_accepted() {
        let sarif = r#"{"runs":[{"tool":{"driver":{
            "name":"t","rules":[{"id":"r","properties":{"security-severity":7.5}}]}},
            "results":[{"ruleId":"r","level":"warning","message":{"text":"m"}}]}]}"#;
        let findings = parse("t", sarif, "/scan").unwrap();
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn clean_kinds_drop_while_detections_and_suppressed_results_surface() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[
            {"ruleId":"r1","kind":"pass","level":"none","message":{"text":"ok"}},
            {"ruleId":"r2","kind":"notApplicable","message":{"text":"n/a"}},
            {"ruleId":"r3","level":"error","message":{"text":"hidden"},"suppressions":[{"status":"accepted"}]},
            {"ruleId":"r4","level":"error","message":{"text":"real"}},
            {"ruleId":"r5","kind":"open","level":"warning","message":{"text":"triage"}},
            {"ruleId":"r6","kind":"review","level":"warning","message":{"text":"judge"}},
            {"ruleId":"r7","kind":"informational","message":{"text":"info"}}
        ]}]}"#;
        let ids: Vec<String> = parse("t", sarif, "/scan")
            .unwrap()
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(
            ids.len(),
            4,
            "open/review/suppressed/fail surface; pass/notApplicable/informational drop"
        );
        for kept in ["r3", "r4", "r5", "r6"] {
            assert!(ids.contains(&kept.to_owned()), "{kept} must surface");
        }
    }

    #[test]
    fn explicit_fail_kind_is_kept() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[
            {"ruleId":"r","kind":"fail","level":"error","message":{"text":"m"}}
        ]}]}"#;
        assert_eq!(parse("t", sarif, "/scan").unwrap().len(), 1);
    }

    #[test]
    fn absent_result_level_falls_back_to_rule_default_configuration() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"t","rules":[
            {"id":"r","defaultConfiguration":{"level":"error"}}
        ]}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}"#;
        let f = parse("t", sarif, "/scan").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High, "error-level rule → High");
    }

    #[test]
    fn multi_location_result_uses_the_first_location() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"},
            "locations":[
                {"physicalLocation":{"artifactLocation":{"uri":"/scan/first.yaml"},"region":{"startLine":1}}},
                {"physicalLocation":{"artifactLocation":{"uri":"/scan/second.yaml"},"region":{"startLine":2}}}
            ]}]}]}"#;
        let findings = parse("t", sarif, "/scan").unwrap();
        assert_eq!(
            findings.len(),
            1,
            "a multi-location result yields one finding"
        );
        assert_eq!(findings[0].file.as_deref(), Some("first.yaml"));
        assert_eq!(findings[0].region.start_line, Some(1));
    }

    #[test]
    fn empty_runs_yield_no_findings() {
        assert!(parse("t", r#"{"runs":[]}"#, "/scan").unwrap().is_empty());
        assert!(parse("t", "{}", "/scan").unwrap().is_empty());
    }

    #[test]
    fn malformed_sarif_is_an_error_not_a_panic() {
        assert!(parse("t", "not json at all", "/scan").is_err());
    }

    #[test]
    fn render_emits_one_run_per_tool_and_round_trips() {
        let findings = vec![
            Finding {
                tool: "gitleaks".to_owned(),
                rule_id: "aws".to_owned(),
                message: "secret".to_owned(),
                severity: Severity::Critical,
                class: RuleClass::Secret,
                file: Some("a.yaml".to_owned()),
                region: Region {
                    start_line: Some(3),
                    ..Region::default()
                },
            },
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "CVE-1".to_owned(),
                message: "vuln".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: None,
                region: Region::default(),
            },
        ];
        let sarif = render(&findings);
        let value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(value["version"], SARIF_VERSION);
        assert_eq!(value["$schema"], SARIF_SCHEMA);
        assert_eq!(value["runs"].as_array().unwrap().len(), 2);
        let reparsed = parse("gitleaks", &sarif, "/scan").unwrap();
        assert!(reparsed.iter().any(|f| f.rule_id == "aws"));
    }

    #[test]
    fn normalize_uri_strips_mount_and_host_roots() {
        assert_eq!(normalize_uri("/scan/config.yaml", "/scan"), "config.yaml");
        assert_eq!(normalize_uri("file:///scan/a.yaml", "/scan"), "a.yaml");
        assert_eq!(normalize_uri("file://scan/a.yaml", "/scan"), "a.yaml");
        assert_eq!(normalize_uri("./a.yaml", "/scan"), "a.yaml");
        // Bare-segment fallback is Docker-only: a host-mode skill's own `scan/` dir stays intact.
        assert_eq!(normalize_uri("scan/foo.py", "/home/u/skill"), "scan/foo.py");
        assert_eq!(
            normalize_uri("/home/u/my-skill/src/x.py", "/home/u/my-skill"),
            "src/x.py"
        );
        // A sibling sharing a prefix is not stripped as a child.
        assert_eq!(normalize_uri("/scanner/x", "/scan"), "scanner/x");
        assert_eq!(
            normalize_uri("already/relative.txt", "/scan"),
            "already/relative.txt"
        );
        assert_eq!(normalize_uri("/scan/scan/foo.py", "/scan"), "scan/foo.py");
        assert_eq!(
            normalize_uri("/home/u/skill/scan/foo.py", "/home/u/skill"),
            "scan/foo.py"
        );
    }

    #[test]
    fn region_columns_survive_render_then_parse() {
        let findings = vec![Finding {
            tool: "trivy".to_owned(),
            rule_id: "r".to_owned(),
            message: "m".to_owned(),
            severity: Severity::High,
            class: RuleClass::Misconfig,
            file: Some("a.tf".to_owned()),
            region: Region {
                start_line: Some(4),
                end_line: Some(6),
                start_column: Some(2),
                end_column: Some(8),
            },
        }];
        let reparsed = parse("trivy", &render(&findings), "/scan").unwrap();
        assert_eq!(reparsed.len(), 1);
        assert_eq!(reparsed[0].file.as_deref(), Some("a.tf"));
        let r = reparsed[0].region;
        assert_eq!(r.start_line, Some(4));
        assert_eq!(r.end_line, Some(6));
        assert_eq!(r.start_column, Some(2));
        assert_eq!(r.end_column, Some(8));
    }
}
