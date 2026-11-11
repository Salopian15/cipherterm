//! "Sealed" messages: ciphertext bundled with the recipe needed to decrypt it,
//! packed into a single opaque block of base64 text (wrapped at 64 columns).
//!
//! Inside the base64 is a small JSON object
//! `{"cipherterm":1,"steps":[...],"body":"<ciphertext>"}`. The app recognises a
//! pasted sealed message by decoding it and finding that marker, so no
//! BEGIN/END lines are needed.
//!
//! Anyone holding a sealed message can decrypt it, so this is for convenience
//! and obfuscation, not secrecy.

use crate::ciphers::Step;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

const WRAP: usize = 64;
const MARKER: &str = "{\"cipherterm\":";

/// Shareable pipeline description (used by export/import recipe).
#[derive(Serialize, Deserialize)]
pub struct Recipe {
    pub cipherterm: u32,
    pub steps: Vec<Step>,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    cipherterm: u32,
    steps: Vec<Step>,
    body: String,
}

pub fn seal(steps: &[Step], ciphertext: &str) -> String {
    // Only the steps that actually ran are needed to undo them.
    let steps: Vec<Step> = steps.iter().filter(|s| s.enabled).cloned().collect();
    let json = serde_json::to_string(&Sealed { cipherterm: 1, steps, body: ciphertext.into() })
        .unwrap_or_default();
    let encoded = B64.encode(json);
    encoded
        .as_bytes()
        .chunks(WRAP)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `None` if `text` isn't a sealed message, otherwise the embedded recipe
/// steps and ciphertext body (or a description of what's wrong with it).
pub fn open(text: &str) -> Option<Result<(Vec<Step>, String), String>> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    // Cheap rejection: the marker always encodes to this prefix.
    if !clean.starts_with("eyJjaXBoZXJ0ZXJtIj") {
        return None;
    }
    let bytes = B64.decode(&clean).ok()?;
    let json = String::from_utf8(bytes).ok()?;
    if !json.starts_with(MARKER) {
        return None;
    }
    Some(
        serde_json::from_str::<Sealed>(&json)
            .map(|s| (s.steps, s.body))
            .map_err(|e| format!("sealed message is corrupted: {e}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphers::{run_pipeline, Cipher, EnigmaConfig, Mode};

    #[test]
    fn seal_and_open_roundtrip() {
        let steps = vec![
            Step { cipher: Cipher::Enigma(EnigmaConfig::default()), enabled: true },
            Step { cipher: Cipher::Caesar { shift: 7 }, enabled: false },
            Step { cipher: Cipher::Vigenere { key: "LEMON".into() }, enabled: true },
            Step { cipher: Cipher::Base64, enabled: true },
        ];
        let plain = "Multi-line\nsecret message!";
        let ct = run_pipeline(&steps, plain, Mode::Encrypt).last().unwrap().result.clone().unwrap();
        let sealed = seal(&steps, &ct);
        assert!(sealed.lines().all(|l| l.len() <= WRAP));
        assert!(!sealed.contains("BEGIN"));

        // Simulate a Windows clipboard round-trip with CRLF and extra padding.
        let pasted = format!("  {}\n", sealed.replace('\n', "\r\n"));
        let (got_steps, body) = open(&pasted).unwrap().unwrap();
        assert_eq!(body, ct);
        assert_eq!(got_steps.len(), 3);
        let dec = run_pipeline(&got_steps, &body, Mode::Decrypt);
        assert_eq!(dec.last().unwrap().result.clone().unwrap(), plain);
    }

    #[test]
    fn non_sealed_and_broken_input() {
        assert!(open("hello").is_none());
        // Ordinary base64 isn't mistaken for a sealed message.
        assert!(open(&B64.encode("just some text")).is_none());
        // Right marker, wrong contents.
        assert!(open(&B64.encode("{\"cipherterm\":1,\"steps\":5}")).unwrap().is_err());
    }
}
