use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    #[serde(default)]
    pub allowed_profiles: HashSet<String>,
    pub profile_types: HashSet<String>,
    pub localhost_profiles: HashSet<String>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        let allowed_profile_types: HashSet<String> = [
            "Localhost".to_string(),
            "RuntimeDefault".to_string(),
            "Unconfined".to_string(),
        ]
        .iter()
        .cloned()
        .collect();

        for profile_type in &self.profile_types {
            if !allowed_profile_types.contains(profile_type) {
                return Err(format!("Invalid Seccomp profile type: {profile_type}"));
            }
            if profile_type == "Localhost" && self.localhost_profiles.is_empty() {
                return Err(
                    "Seccomp type 'Localhost' requires some 'localhost_profiles' value "
                        .to_string(),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kubewarden::settings::Validatable;
    use anyhow::Result;

    macro_rules! configuration {
        (allowed_profiles: $allowed_profiles:expr, profile_types: $profile_types:expr, localhost_profiles: $localhost_profiles: expr) => {
            &Settings {
                allowed_profiles: $allowed_profiles.split(",").map(String::from).collect(),
                profile_types: $profile_types.split(",").map(String::from).collect(),
                localhost_profiles: $localhost_profiles.split(",").map(String::from).collect(),
            }
        };
    }

    #[test]
    fn test_allowed_profile_types() -> Result<()> {
        let settings = configuration!(allowed_profiles: "runtime/default,docker/default,localhost/test", profile_types: "RuntimeDefault,Localhost,Unconfined", localhost_profiles: "test");
        assert!(settings.validate().is_ok());
        Ok(())
    }

    #[test]
    fn test_disallowed_profile_types() -> Result<()> {
        let settings = configuration!(allowed_profiles: "runtime/default,docker/default,localhost/test", profile_types: "RuntimeDefault,Localhost,Dummy", localhost_profiles: "test");
        assert!(settings.validate().is_err());
        Ok(())
    }
}
