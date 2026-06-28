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
}

impl Config {
    /// Load from the default config path, then apply env-var and CLI overrides.
    #[allow(dead_code)]
    pub fn load(cli_provider: Option<&str>, cli_model: Option<&str>, cli_api_key: Option<&str>) -> Self {
        Self::load_with_base_url(cli_provider, cli_model, cli_api_key, None, false, None)
    }

    pub fn load_with_base_url(cli_provider: Option<&str>, cli_model: Option<&str>, cli_api_key: Option<&str>, cli_base_url: Option<&str>, cli_no_thinking: bool, cli_effort: Option<&str>) -> Self {
        let file_cfg = Self::load_file();

        // Precedence for each setting: CLI flag > environment variable > config file > default.
        let provider = cli_provider
            .map(|s| s.to_string())
            .or_else(|| env_var("CHENNAI_PROVIDER"))
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
            .or(file_cfg.base_url);

        let api_key = cli_api_key
            .map(|s| s.to_string())
            .or_else(|| Self::key_from_env(&provider));

        let enabled = api_key.is_some();

        let effort = cli_effort
            .map(|s| s.to_string())
            .or(file_cfg.effort)
            .unwrap_or_else(|| "high".to_string());

        Config { provider, model, base_url, api_key, enabled, no_thinking: cli_no_thinking, effort, debug: false }
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
        PathBuf::from(home).join(".config").join("chennai").join("config.toml")
    }

    /// Read the provider-specific API key from the expected environment variable.
    fn key_from_env(provider: &ProviderKind) -> Option<String> {
        let var = match provider {
            ProviderKind::Anthropic => "ANTHROPIC_API_KEY",
            ProviderKind::OpenAI => "OPENAI_API_KEY",
        };
        std::env::var(var).ok().filter(|s| !s.is_empty())
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

    #[test]
    fn provider_kind_parsing() {
        assert_eq!("anthropic".parse::<ProviderKind>().unwrap(), ProviderKind::Anthropic);
        assert_eq!("Anthropic".parse::<ProviderKind>().unwrap(), ProviderKind::Anthropic);
        assert_eq!("openai".parse::<ProviderKind>().unwrap(), ProviderKind::OpenAI);
        assert_eq!("openai-compatible".parse::<ProviderKind>().unwrap(), ProviderKind::OpenAI);
        assert!("unknown".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn default_model_is_opus_4_8() {
        // §1.6: never a deprecated date-suffixed snapshot.
        assert_eq!(default_model(), "claude-opus-4-8");
    }

    #[test]
    fn default_effort_is_high() {
        let cfg = Config::load(None, None, None);
        assert_eq!(cfg.effort, "high");
    }

    #[test]
    fn cli_effort_overrides_default() {
        let cfg = Config::load_with_base_url(None, None, None, None, false, Some("xhigh"));
        assert_eq!(cfg.effort, "xhigh");
    }

    #[test]
    fn load_with_cli_overrides() {
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
            if let Some(k) = prev_anthropic { std::env::set_var("ANTHROPIC_API_KEY", k); }
            if let Some(k) = prev_openai { std::env::set_var("OPENAI_API_KEY", k); }
        }
    }

    #[test]
    fn env_vars_set_provider_model_base_url_and_cli_overrides_env() {
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
        let cfg = Config::load_with_base_url(None, None, None, None, false, None);
        assert_eq!(cfg.provider, ProviderKind::OpenAI);
        assert_eq!(cfg.model, "gpt-4o");
        assert_eq!(cfg.base_url.as_deref(), Some("https://example.test/v1"));

        // CLI flags take precedence over env vars.
        let cfg = Config::load_with_base_url(
            Some("anthropic"), Some("claude-x"), None, Some("https://cli.test"), false, None,
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
        assert!(Config::key_from_env(&ProviderKind::Anthropic).is_none());
        // Set and test
        unsafe { std::env::set_var("ANTHROPIC_API_KEY", "sk-test-xxx"); }
        let key = Config::key_from_env(&ProviderKind::Anthropic);
        assert_eq!(key.as_deref(), Some("sk-test-xxx"));
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY"); }
    }
}
