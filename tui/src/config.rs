//! Agent configuration loaded from `~/.config/chennai/config.toml`, environment variables, and CLI
//! overrides. Follows the convention: CLI > env > config file > defaults.

use serde::Deserialize;
use std::path::PathBuf;

/// Provider kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenAI,
}

impl std::str::FromStr for ProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "anthropic" => Ok(ProviderKind::Anthropic),
            "openai" | "openai-compatible" => Ok(ProviderKind::OpenAI),
            other => Err(format!(
                "unknown provider '{other}'; expected 'anthropic' or 'openai'"
            )),
        }
    }
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderKind::Anthropic => write!(f, "anthropic"),
            ProviderKind::OpenAI => write!(f, "openai"),
        }
    }
}

/// The on-disk config shape (TOML).
#[derive(Debug, Clone, Default, Deserialize)]
struct FileConfig {
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    effort: Option<String>,
}

/// Resolved agent configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub provider: ProviderKind,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub enabled: bool,
    /// Anthropic `output_config.effort` (`low` | `medium` | `high` | `xhigh` | `max`).
    /// Defaults to `high`; ignored by providers that don't support it.
    pub effort: String,
    /// When true, omit the `thinking` block from request bodies (for providers that don't support
    /// Anthropic's adaptive thinking parameter, e.g. DeepSeek's Anthropic-compatible endpoint).
    pub no_thinking: bool,
    /// When true, tool calls (atom_*, bom_*, rusi_*, golem_*, dosai_*, blint_*)
    /// are logged to timestamped JSON files under `.chen/chennai-debug-logs/`.
    pub debug: bool,
    /// When true, the agent uses the orchestrator loop which delegates analysis
    /// to focused sub-agents with isolated contexts.
    pub orchestrate: bool,
    /// Maximum number of sub-agents the orchestrator may spawn in a single run.
    /// Hard cap — the one guaranteed termination backstop. Default 8.
    pub max_subagents: usize,
    /// Advisory global turn budget. When exceeded, a warning is surfaced but
    /// sub-agents are still spawned. Default 80.
    pub turn_budget: u64,
    /// Advisory global token budget. When exceeded, a warning is surfaced but
    /// sub-agents are still spawned. Default 256,000. Hard ceiling — no
    /// configuration source can raise it above this value.
    pub token_budget: u64,
}

impl Config {
    /// Load from the default config path, then apply env-var and CLI overrides.
    #[allow(dead_code)]
    pub fn load(
        cli_provider: Option<&str>,
        cli_model: Option<&str>,
        cli_api_key: Option<&str>,
    ) -> Self {
        Self::load_with_base_url(
            cli_provider,
            cli_model,
            cli_api_key,
            None,
            false,
            None,
            false,
            None,
            None,
            None,
        )
    }

    // One CLI parameter per user-facing flag; precedence resolution keeps them
    // separate rather than bundling into a struct that would just be unpacked here.
    #[allow(clippy::too_many_arguments)]
    pub fn load_with_base_url(
        cli_provider: Option<&str>,
        cli_model: Option<&str>,
        cli_api_key: Option<&str>,
        cli_base_url: Option<&str>,
        cli_no_thinking: bool,
        cli_effort: Option<&str>,
        cli_orchestrate: bool,
        cli_max_subagents: Option<usize>,
        cli_turn_budget: Option<u64>,
        cli_token_budget: Option<u64>,
    ) -> Self {
        let file_cfg = Self::load_file();

        // Precedence for the provider: explicit choice (CLI flag or CHENNAI_PROVIDER) >
        // inferred from Anthropic env vars > config file > default. An Anthropic auth
        // token or base URL in the environment (as set by Claude Code and Anthropic
        // gateways) implies the anthropic provider unless the user chose one explicitly.
        let anthropic_env_present =
            env_var("ANTHROPIC_AUTH_TOKEN").is_some() || env_var("ANTHROPIC_BASE_URL").is_some();
        let provider = cli_provider
            .map(|s| s.to_string())
            .or_else(|| env_var("CHENNAI_PROVIDER"))
            .or_else(|| anthropic_env_present.then(|| "anthropic".to_string()))
            .or(file_cfg.provider)
            .unwrap_or_else(|| "anthropic".to_string());
        let provider: ProviderKind = provider.parse().unwrap_or(ProviderKind::Anthropic);

        let model = cli_model
            .map(|s| s.to_string())
            .or_else(|| env_var("CHENNAI_MODEL"))
            .or(file_cfg.model)
            .unwrap_or_else(default_model);

        let base_url = cli_base_url
            .map(|s| s.to_string())
            .or_else(|| env_var("CHENNAI_BASE_URL"))
            .or_else(|| {
                // Honor Claude Code's `ANTHROPIC_BASE_URL` when targeting Anthropic.
                if provider == ProviderKind::Anthropic {
                    env_var("ANTHROPIC_BASE_URL")
                } else {
                    None
                }
            })
            .or(file_cfg.base_url);

        let api_key = cli_api_key
            .map(|s| s.to_string())
            .or_else(|| Self::key_from_env(&provider));

        let enabled = api_key.is_some();

        let effort = cli_effort
            .map(|s| s.to_string())
            .or(file_cfg.effort)
            .unwrap_or_else(|| "high".to_string());

        let max_subagents = cli_max_subagents
            .or_else(|| env_var("CHENNAI_MAX_SUBAGENTS").and_then(|s| s.parse::<usize>().ok()))
            .unwrap_or(8);

        let turn_budget = cli_turn_budget
            .or_else(|| env_var("CHENNAI_TURN_BUDGET").and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(80);

        let token_budget = cli_token_budget
            .or_else(|| env_var("CHENNAI_TOKEN_BUDGET").and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(crate::agent::roles::TOKEN_BUDGET_CEILING);

        // Clamp the token budget to the hard ceiling. Configuration sources
        // (CLI, env, or project manifest) may only *lower* this value.
        let (token_budget, was_clamped) = crate::agent::roles::clamp_token_budget(token_budget);
        if was_clamped {
            eprintln!(
                "[config] token_budget clamped to {} (requested value exceeded the hard ceiling)",
                token_budget
            );
        }

        // Orchestrated mode is enabled by the `--orchestrate` CLI flag or the
        // user-controlled `CHENNAI_ORCHESTRATE` env var. A project manifest can
        // never turn it on — only the shape of a run, not its initiation.
        let orchestrate = cli_orchestrate
            || env_var("CHENNAI_ORCHESTRATE")
                .map(|s| {
                    matches!(
                        s.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(false);

        Config {
            provider,
            model,
            base_url,
            api_key,
            enabled,
            no_thinking: cli_no_thinking,
            effort,
            debug: false,
            orchestrate,
            max_subagents,
            turn_budget,
            token_budget,
        }
    }

    /// Read the config file at `~/.config/chennai/config.toml`.
    fn load_file() -> FileConfig {
        let path = Self::config_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|content| toml::from_str::<FileConfig>(&content).ok())
            .unwrap_or_default()
    }

    /// Path to the per-user config file.
    fn config_path() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        PathBuf::from(home)
            .join(".config")
            .join("chennai")
            .join("config.toml")
    }

    /// Read the provider-specific API key from the expected environment variables.
    /// For Anthropic, `ANTHROPIC_API_KEY` takes precedence over `ANTHROPIC_AUTH_TOKEN`
    /// (the latter is the variable Claude Code and Anthropic-compatible gateways set).
    fn key_from_env(provider: &ProviderKind) -> Option<String> {
        let vars: &[&str] = match provider {
            ProviderKind::Anthropic => &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
            ProviderKind::OpenAI => &["OPENAI_API_KEY"],
        };
        vars.iter().find_map(|v| env_var(v))
    }
}

/// Read an environment variable, treating an empty value as unset.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn default_model() -> String {
    // Plan default: Anthropic Opus 4.8. Use the bare alias, never a date-suffixed
    // snapshot (those are deprecated and 404 after retirement).
    "claude-opus-4-8".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn provider_kind_parsing() {
        assert_eq!(
            "anthropic".parse::<ProviderKind>().unwrap(),
            ProviderKind::Anthropic
        );
        assert_eq!(
            "Anthropic".parse::<ProviderKind>().unwrap(),
            ProviderKind::Anthropic
        );
        assert_eq!(
            "openai".parse::<ProviderKind>().unwrap(),
            ProviderKind::OpenAI
        );
        assert_eq!(
            "openai-compatible".parse::<ProviderKind>().unwrap(),
            ProviderKind::OpenAI
        );
        assert!("unknown".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn default_model_is_opus_4_8() {
        // §1.6: never a deprecated date-suffixed snapshot.
        assert_eq!(default_model(), "claude-opus-4-8");
    }

    #[test]
    fn default_effort_is_high() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load(None, None, None);
        assert_eq!(cfg.effort, "high");
    }

    #[test]
    fn cli_effort_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            Some("xhigh"),
            false,
            None,
            None,
            None,
        );
        assert_eq!(cfg.effort, "xhigh");
    }

    #[test]
    fn load_with_cli_overrides() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Without env var, config loading gracefully produces disabled config.
        let prev_anthropic = std::env::var("ANTHROPIC_API_KEY").ok();
        let prev_openai = std::env::var("OPENAI_API_KEY").ok();
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");
        }
        let cfg = Config::load(Some("openai"), Some("gpt-4o"), None);
        assert_eq!(cfg.provider, ProviderKind::OpenAI);
        assert_eq!(cfg.model, "gpt-4o");
        assert!(!cfg.enabled);
        // Restore env vars.
        unsafe {
            if let Some(k) = prev_anthropic {
                std::env::set_var("ANTHROPIC_API_KEY", k);
            }
            if let Some(k) = prev_openai {
                std::env::set_var("OPENAI_API_KEY", k);
            }
        }
    }

    #[test]
    fn env_vars_set_provider_model_base_url_and_cli_overrides_env() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = [
            ("CHENNAI_PROVIDER", std::env::var("CHENNAI_PROVIDER").ok()),
            ("CHENNAI_MODEL", std::env::var("CHENNAI_MODEL").ok()),
            ("CHENNAI_BASE_URL", std::env::var("CHENNAI_BASE_URL").ok()),
        ];
        unsafe {
            std::env::set_var("CHENNAI_PROVIDER", "openai");
            std::env::set_var("CHENNAI_MODEL", "gpt-4o");
            std::env::set_var("CHENNAI_BASE_URL", "https://example.test/v1");
        }

        // Env vars apply when no CLI flags are given.
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert_eq!(cfg.provider, ProviderKind::OpenAI);
        assert_eq!(cfg.model, "gpt-4o");
        assert_eq!(cfg.base_url.as_deref(), Some("https://example.test/v1"));

        // CLI flags take precedence over env vars.
        let cfg = Config::load_with_base_url(
            Some("anthropic"),
            Some("claude-x"),
            None,
            Some("https://cli.test"),
            false,
            None,
            false,
            None,
            None,
            None,
        );
        assert_eq!(cfg.provider, ProviderKind::Anthropic);
        assert_eq!(cfg.model, "claude-x");
        assert_eq!(cfg.base_url.as_deref(), Some("https://cli.test"));

        unsafe {
            for (k, v) in prev {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn key_from_env_checks_correct_var() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("ANTHROPIC_API_KEY").ok();
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
        }

        assert!(Config::key_from_env(&ProviderKind::Anthropic).is_none());
        // Set and test
        unsafe {
            std::env::set_var("ANTHROPIC_API_KEY", "sk-test-xxx");
        }
        let key = Config::key_from_env(&ProviderKind::Anthropic);
        assert_eq!(key.as_deref(), Some("sk-test-xxx"));

        unsafe {
            match prev {
                Some(val) => std::env::set_var("ANTHROPIC_API_KEY", val),
                None => std::env::remove_var("ANTHROPIC_API_KEY"),
            }
        }
    }

    #[test]
    fn key_from_env_falls_back_to_auth_token() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev_key = std::env::var("ANTHROPIC_API_KEY").ok();
        let prev_tok = std::env::var("ANTHROPIC_AUTH_TOKEN").ok();
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::set_var("ANTHROPIC_AUTH_TOKEN", "tok-xyz");
        }
        // With no ANTHROPIC_API_KEY, the auth-token variable is used.
        assert_eq!(
            Config::key_from_env(&ProviderKind::Anthropic).as_deref(),
            Some("tok-xyz")
        );
        // ANTHROPIC_API_KEY, when present, wins over ANTHROPIC_AUTH_TOKEN.
        unsafe {
            std::env::set_var("ANTHROPIC_API_KEY", "sk-primary");
        }
        assert_eq!(
            Config::key_from_env(&ProviderKind::Anthropic).as_deref(),
            Some("sk-primary")
        );
        unsafe {
            match prev_key {
                Some(v) => std::env::set_var("ANTHROPIC_API_KEY", v),
                None => std::env::remove_var("ANTHROPIC_API_KEY"),
            }
            match prev_tok {
                Some(v) => std::env::set_var("ANTHROPIC_AUTH_TOKEN", v),
                None => std::env::remove_var("ANTHROPIC_AUTH_TOKEN"),
            }
        }
    }

    #[test]
    fn anthropic_base_url_env_used_for_anthropic_provider() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev_chennai = std::env::var("CHENNAI_BASE_URL").ok();
        let prev_anthropic = std::env::var("ANTHROPIC_BASE_URL").ok();
        unsafe {
            std::env::remove_var("CHENNAI_BASE_URL");
            std::env::set_var("ANTHROPIC_BASE_URL", "https://gateway.test/anthropic");
        }
        // Anthropic provider honors ANTHROPIC_BASE_URL when CHENNAI_BASE_URL is unset.
        let cfg = Config::load_with_base_url(
            Some("anthropic"),
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            None,
        );
        assert_eq!(
            cfg.base_url.as_deref(),
            Some("https://gateway.test/anthropic")
        );
        // CHENNAI_BASE_URL takes precedence when both are set.
        unsafe {
            std::env::set_var("CHENNAI_BASE_URL", "https://primary.test/v1");
        }
        let cfg = Config::load_with_base_url(
            Some("anthropic"),
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            None,
        );
        assert_eq!(cfg.base_url.as_deref(), Some("https://primary.test/v1"));
        unsafe {
            match prev_chennai {
                Some(v) => std::env::set_var("CHENNAI_BASE_URL", v),
                None => std::env::remove_var("CHENNAI_BASE_URL"),
            }
            match prev_anthropic {
                Some(v) => std::env::set_var("ANTHROPIC_BASE_URL", v),
                None => std::env::remove_var("ANTHROPIC_BASE_URL"),
            }
        }
    }

    #[test]
    fn anthropic_env_infers_provider() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev_prov = std::env::var("CHENNAI_PROVIDER").ok();
        let prev_tok = std::env::var("ANTHROPIC_AUTH_TOKEN").ok();
        unsafe {
            std::env::remove_var("CHENNAI_PROVIDER");
            std::env::set_var("ANTHROPIC_AUTH_TOKEN", "tok-infer");
        }
        // No explicit provider, but an Anthropic auth token is set → anthropic.
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert_eq!(cfg.provider, ProviderKind::Anthropic);
        // An explicit CLI provider still wins over the inference.
        let cfg = Config::load_with_base_url(
            Some("openai"),
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            None,
        );
        assert_eq!(cfg.provider, ProviderKind::OpenAI);
        unsafe {
            match prev_prov {
                Some(v) => std::env::set_var("CHENNAI_PROVIDER", v),
                None => std::env::remove_var("CHENNAI_PROVIDER"),
            }
            match prev_tok {
                Some(v) => std::env::set_var("ANTHROPIC_AUTH_TOKEN", v),
                None => std::env::remove_var("ANTHROPIC_AUTH_TOKEN"),
            }
        }
    }

    #[test]
    fn budget_defaults_match_expected() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert_eq!(cfg.max_subagents, 8);
        assert_eq!(cfg.turn_budget, 80);
        assert_eq!(cfg.token_budget, 256_000);
    }

    #[test]
    fn cli_max_subagents_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            Some(12),
            None,
            None,
        );
        assert_eq!(cfg.max_subagents, 12);
    }

    #[test]
    fn cli_turn_budget_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            Some(200),
            None,
        );
        assert_eq!(cfg.turn_budget, 200);
    }

    #[test]
    fn cli_token_budget_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            Some(200_000),
        );
        assert_eq!(cfg.token_budget, 200_000);
    }

    #[test]
    fn cli_token_budget_clamped_to_ceiling() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            Some(3_000_000),
        );
        assert_eq!(
            cfg.token_budget, 256_000,
            "values above the ceiling must be clamped"
        );
    }

    #[test]
    fn env_var_max_subagents_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CHENNAI_MAX_SUBAGENTS").ok();
        unsafe {
            std::env::set_var("CHENNAI_MAX_SUBAGENTS", "16");
        }
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert_eq!(cfg.max_subagents, 16);
        unsafe {
            match prev {
                Some(val) => std::env::set_var("CHENNAI_MAX_SUBAGENTS", val),
                None => std::env::remove_var("CHENNAI_MAX_SUBAGENTS"),
            }
        }
    }

    #[test]
    fn env_var_turn_budget_overrides_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CHENNAI_TURN_BUDGET").ok();
        unsafe {
            std::env::set_var("CHENNAI_TURN_BUDGET", "200");
        }
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert_eq!(cfg.turn_budget, 200);
        unsafe {
            match prev {
                Some(val) => std::env::set_var("CHENNAI_TURN_BUDGET", val),
                None => std::env::remove_var("CHENNAI_TURN_BUDGET"),
            }
        }
    }

    #[test]
    fn cli_budget_overrides_env_var() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CHENNAI_TOKEN_BUDGET").ok();
        unsafe {
            std::env::set_var("CHENNAI_TOKEN_BUDGET", "5_000_000");
        }
        // CLI overrides env var — value is within the ceiling so it passes through.
        let cfg = Config::load_with_base_url(
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            None,
            Some(200_000),
        );
        assert_eq!(cfg.token_budget, 200_000);
        unsafe {
            match prev {
                Some(val) => std::env::set_var("CHENNAI_TOKEN_BUDGET", val),
                None => std::env::remove_var("CHENNAI_TOKEN_BUDGET"),
            }
        }
    }

    #[test]
    fn env_var_enables_orchestrate() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CHENNAI_ORCHESTRATE").ok();

        unsafe {
            std::env::set_var("CHENNAI_ORCHESTRATE", "true");
        }
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert!(
            cfg.orchestrate,
            "CHENNAI_ORCHESTRATE=true should enable orchestration"
        );

        unsafe {
            std::env::set_var("CHENNAI_ORCHESTRATE", "0");
        }
        let cfg = Config::load_with_base_url(
            None, None, None, None, false, None, false, None, None, None,
        );
        assert!(
            !cfg.orchestrate,
            "CHENNAI_ORCHESTRATE=0 should not enable orchestration"
        );

        // CLI flag wins regardless of env.
        unsafe {
            std::env::set_var("CHENNAI_ORCHESTRATE", "0");
        }
        let cfg =
            Config::load_with_base_url(None, None, None, None, false, None, true, None, None, None);
        assert!(
            cfg.orchestrate,
            "--orchestrate should enable even when env is off"
        );

        unsafe {
            match prev {
                Some(val) => std::env::set_var("CHENNAI_ORCHESTRATE", val),
                None => std::env::remove_var("CHENNAI_ORCHESTRATE"),
            }
        }
    }
}
