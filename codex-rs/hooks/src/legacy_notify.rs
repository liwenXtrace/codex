use std::ffi::OsString;
use std::process::Stdio;
use std::sync::Arc;

use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Serialize;

use crate::Hook;
use crate::HookEvent;
use crate::HookPayload;
use crate::HookResult;
use crate::registry::command_from_argv;

/// Legacy notify payload appended as the final argv argument for backward compatibility.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum UserNotification {
    #[serde(rename_all = "kebab-case")]
    AgentTurnComplete {
        thread_id: String,
        turn_id: String,
        cwd: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        input_messages: Vec<String>,
        last_assistant_message: Option<String>,
    },
}

pub fn legacy_notify_json(payload: &HookPayload) -> Result<String, serde_json::Error> {
    match &payload.hook_event {
        HookEvent::AfterAgent { event } => {
            serde_json::to_string(&UserNotification::AgentTurnComplete {
                thread_id: event.thread_id.to_string(),
                turn_id: event.turn_id.clone(),
                cwd: payload.cwd.display().to_string(),
                client: payload.client.clone(),
                input_messages: event.input_messages.clone(),
                last_assistant_message: event.last_assistant_message.clone(),
            })
        }
    }
}

// TODO: Remove this hook and its environment plumbing when legacy `notify` support is removed.
pub(crate) fn notify_hook(
    argv: Vec<String>,
    environment: Arc<Vec<(OsString, OsString)>>,
    read_only_paths: Result<Vec<AbsolutePathBuf>, String>,
) -> Hook {
    let argv = Arc::new(argv);
    Hook {
        name: "legacy_notify".to_string(),
        func: Arc::new(move |payload: &HookPayload| {
            let argv = Arc::clone(&argv);
            let environment = Arc::clone(&environment);
            let read_only_paths = read_only_paths.clone();
            Box::pin(async move {
                let paths = match read_only_paths {
                    Ok(paths) => paths,
                    Err(error) => return HookResult::FailedContinue(anyhow::anyhow!(error).into()),
                };
                let argv = match argv.split_first() {
                    Some((program, args)) => match codex_sandboxing::protect_read_only_paths(
                        program.clone(),
                        args.to_vec(),
                        payload.cwd.as_path(),
                        &paths,
                    ) {
                        Ok(argv) => argv,
                        Err(error) => return HookResult::FailedContinue(error.into()),
                    },
                    None => return HookResult::Success,
                };
                let mut command = match command_from_argv(&argv, environment.iter().cloned()) {
                    Some(command) => command,
                    None => return HookResult::Success,
                };
                if let Ok(notify_payload) = legacy_notify_json(payload) {
                    command.arg(notify_payload);
                }

                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                match command.spawn() {
                    Ok(_) => HookResult::Success,
                    Err(err) => HookResult::FailedContinue(err.into()),
                }
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use codex_protocol::ThreadId;
    use codex_protocol::shell_environment::CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN_ENV_VAR;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;
    use pretty_assertions::assert_eq;
    use serde_json::Value;
    use serde_json::json;

    use super::*;
    use crate::HookEventAfterAgent;

    fn expected_notification_json() -> Value {
        let cwd = test_path_buf("/Users/example/project");
        json!({
            "type": "agent-turn-complete",
            "thread-id": "b5f6c1c2-1111-2222-3333-444455556666",
            "turn-id": "12345",
            "cwd": cwd.display().to_string(),
            "client": "codex-tui",
            "input-messages": ["Rename `foo` to `bar` and update the callsites."],
            "last-assistant-message": "Rename complete and verified `cargo build` succeeds.",
        })
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn notify_preserves_payload_but_denies_source_writes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("source");
        let branch = dir.path().join("branch");
        std::fs::create_dir_all(&source)?;
        std::fs::create_dir_all(&branch)?;
        let result = branch.join("result");
        let script = format!(
            "if /bin/sh -c 'echo escaped > \"$1/forbidden\"' child \"{}\"; then exit 99; fi; printf '%s' \"$1\" > \"{}\"",
            source.display(),
            result.display()
        );
        let hook = notify_hook(
            vec!["/bin/sh".into(), "-c".into(), script, "notify".into()],
            Arc::new(Vec::new()),
            Ok(vec![AbsolutePathBuf::from_absolute_path(&source)?]),
        );
        let payload = HookPayload {
            session_id: ThreadId::new(),
            cwd: AbsolutePathBuf::from_absolute_path(&branch)?,
            client: None,
            triggered_at: chrono::Utc::now(),
            hook_event: HookEvent::AfterAgent {
                event: HookEventAfterAgent {
                    thread_id: ThreadId::new(),
                    turn_id: "protected".into(),
                    input_messages: vec!["notify".into()],
                    last_assistant_message: Some("done".into()),
                },
            },
        };
        assert!(matches!((hook.func)(&payload).await, HookResult::Success));
        let expected = legacy_notify_json(&payload)?;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while std::fs::read_to_string(&result).ok().as_ref() != Some(&expected) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await?;
        assert!(!source.join("forbidden").exists());
        assert_eq!(std::fs::read_to_string(result)?, expected);
        Ok(())
    }

    #[test]
    fn test_user_notification() -> Result<()> {
        let notification = UserNotification::AgentTurnComplete {
            thread_id: "b5f6c1c2-1111-2222-3333-444455556666".to_string(),
            turn_id: "12345".to_string(),
            cwd: test_path_buf("/Users/example/project")
                .display()
                .to_string(),
            client: Some("codex-tui".to_string()),
            input_messages: vec!["Rename `foo` to `bar` and update the callsites.".to_string()],
            last_assistant_message: Some(
                "Rename complete and verified `cargo build` succeeds.".to_string(),
            ),
        };
        let serialized = serde_json::to_string(&notification)?;
        let actual: Value = serde_json::from_str(&serialized)?;
        assert_eq!(actual, expected_notification_json());
        Ok(())
    }

    #[test]
    fn legacy_notify_json_matches_historical_wire_shape() -> Result<()> {
        let payload = HookPayload {
            session_id: ThreadId::new(),
            cwd: test_path_buf("/Users/example/project").abs(),
            client: Some("codex-tui".to_string()),
            triggered_at: chrono::Utc::now(),
            hook_event: HookEvent::AfterAgent {
                event: HookEventAfterAgent {
                    thread_id: ThreadId::from_string("b5f6c1c2-1111-2222-3333-444455556666")
                        .expect("valid thread id"),
                    turn_id: "12345".to_string(),
                    input_messages: vec![
                        "Rename `foo` to `bar` and update the callsites.".to_string(),
                    ],
                    last_assistant_message: Some(
                        "Rename complete and verified `cargo build` succeeds.".to_string(),
                    ),
                },
            },
        };

        let serialized = legacy_notify_json(&payload)?;
        let actual: Value = serde_json::from_str(&serialized)?;
        assert_eq!(actual, expected_notification_json());

        Ok(())
    }

    #[test]
    fn legacy_notify_command_replays_session_snapshot_and_scrubs_credentials() {
        let argv = vec!["notify-command".to_string()];
        let environment = vec![
            (
                OsString::from("CODEX_LEGACY_NOTIFY_SNAPSHOT"),
                OsString::from("captured"),
            ),
            (
                OsString::from(CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN_ENV_VAR),
                OsString::from("restricted-token"),
            ),
        ];

        let command = command_from_argv(&argv, environment)
            .expect("legacy notification command should be configured");
        let configured_environment = command
            .as_std()
            .get_envs()
            .filter_map(|(name, value)| {
                value.map(|value| (name.to_os_string(), value.to_os_string()))
            })
            .collect::<Vec<_>>();

        assert_eq!(
            configured_environment,
            vec![(
                OsString::from("CODEX_LEGACY_NOTIFY_SNAPSHOT"),
                OsString::from("captured"),
            )]
        );
    }
}
