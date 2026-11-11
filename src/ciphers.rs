//! Cipher and encoding implementations plus the pipeline runner.
//!
//! Every cipher works on `String -> String` so steps can be chained freely.
//! Byte-producing ciphers (XOR) emit hex so the result stays printable.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

pub type CResult = Result<String, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnigmaConfig {
    /// Rotor indices (0 = I .. 4 = V), ordered left, middle, right.
    pub rotors: [usize; 3],
    /// 0 = UKW-B, 1 = UKW-C
    pub reflector: usize,
    /// Start positions, e.g. "AAA".
    pub positions: String,
    /// Ring settings, e.g. "AAA".
    pub rings: String,
    /// Plugboard pairs separated by spaces, e.g. "AB CD EF".
    pub plugboard: String,
}

impl Default for EnigmaConfig {
    fn default() -> Self {
        Self {
            rotors: [0, 1, 2],
            reflector: 0,
            positions: "AAA".into(),
            rings: "AAA".into(),
            plugboard: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Cipher {
    Caesar { shift: i32 },
    Rot13,
    Atbash,
    Vigenere { key: String },
    Affine { a: i32, b: i32 },
    RailFence { rails: usize },
    Columnar { key: String },
    Enigma(EnigmaConfig),
    Xor { key: String },
    Base64,
    Hex,
    Binary,
    Morse,
    Reverse,
    Zodiac,
    Emoji,
    Braille,
    Nato,
    Bacon,
    Invisible { cover: String },
}

impl Cipher {
    /// One default instance of every cipher, in menu order.
    pub fn catalog() -> Vec<Cipher> {
        vec![
            Cipher::Caesar { shift: 3 },
            Cipher::Rot13,
            Cipher::Atbash,
            Cipher::Vigenere { key: "LEMON".into() },
            Cipher::Affine { a: 5, b: 8 },
            Cipher::RailFence { rails: 3 },
            Cipher::Columnar { key: "ZEBRA".into() },
            Cipher::Enigma(EnigmaConfig::default()),
            Cipher::Xor { key: "secret".into() },
            Cipher::Base64,
            Cipher::Hex,
            Cipher::Binary,
            Cipher::Morse,
            Cipher::Reverse,
            Cipher::Zodiac,
            Cipher::Emoji,
            Cipher::Braille,
            Cipher::Nato,
            Cipher::Bacon,
            Cipher::Invisible { cover: "nothing to see here".into() },
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Cipher::Caesar { .. } => "caesar",
            Cipher::Rot13 => "rot13",
            Cipher::Atbash => "atbash",
            Cipher::Vigenere { .. } => "vigenere",
            Cipher::Affine { .. } => "affine",
            Cipher::RailFence { .. } => "rail-fence",
            Cipher::Columnar { .. } => "columnar",
            Cipher::Enigma(_) => "enigma-m3",
            Cipher::Xor { .. } => "xor",
            Cipher::Base64 => "base64",
            Cipher::Hex => "hex",
            Cipher::Binary => "binary",
            Cipher::Morse => "morse",
            Cipher::Reverse => "reverse",
            Cipher::Zodiac => "zodiac",
            Cipher::Emoji => "emoji",
            Cipher::Braille => "braille",
            Cipher::Nato => "nato",
            Cipher::Bacon => "bacon",
            Cipher::Invisible { .. } => "invisible",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Cipher::Caesar { .. } => "shift every letter by N places",
            Cipher::Rot13 => "caesar shift of 13 (self-inverse)",
            Cipher::Atbash => "mirror the alphabet A<->Z",
            Cipher::Vigenere { .. } => "polyalphabetic shift driven by a keyword",
            Cipher::Affine { .. } => "E(x) = (a*x + b) mod 26",
            Cipher::RailFence { .. } => "zig-zag transposition across N rails",
            Cipher::Columnar { .. } => "columnar transposition ordered by keyword",
            Cipher::Enigma(_) => "3-rotor Wehrmacht Enigma, plugboard + rings",
            Cipher::Xor { .. } => "repeating-key XOR, output as hex",
            Cipher::Base64 => "base64 encoding",
            Cipher::Hex => "hexadecimal encoding of UTF-8 bytes",
            Cipher::Binary => "8-bit binary of UTF-8 bytes",
            Cipher::Morse => "international morse (uppercases text)",
            Cipher::Reverse => "reverse the character order",
            Cipher::Zodiac => "letters become zodiac & planet symbols",
            Cipher::Emoji => "picture alphabet: A=apple, B=banana...",
            Cipher::Braille => "letters become braille cells",
            Cipher::Nato => "NATO phonetic alphabet (Alfa Bravo...)",
            Cipher::Bacon => "Bacon's cipher: letters as AABAB groups",
            Cipher::Invisible { .. } => "hide text as zero-width chars in a cover line",
        }
    }

    pub fn apply(&self, input: &str, mode: Mode) -> CResult {
        let enc = mode == Mode::Encrypt;
        match self {
            Cipher::Caesar { shift } => Ok(caesar(input, if enc { *shift } else { -*shift })),
            Cipher::Rot13 => Ok(caesar(input, 13)),
            Cipher::Atbash => Ok(map_letters(input, |x| 25 - x)),
            Cipher::Vigenere { key } => vigenere(input, key, enc),
            Cipher::Affine { a, b } => affine(input, *a, *b, enc),
            Cipher::RailFence { rails } => rail_fence(input, *rails, enc),
            Cipher::Columnar { key } => columnar(input, key, enc),
            Cipher::Enigma(cfg) => enigma(input, cfg),
            Cipher::Xor { key } => xor(input, key, enc),
            Cipher::Base64 => {
                if enc {
                    Ok(B64.encode(input.as_bytes()))
                } else {
                    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
                    let bytes = B64.decode(clean).map_err(|e| format!("invalid base64: {e}"))?;
                    utf8(bytes)
                }
            }
            Cipher::Hex => {
                if enc {
                    Ok(to_hex(input.as_bytes()))
                } else {
                    utf8(from_hex(input)?)
                }
            }
            Cipher::Binary => binary(input, enc),
            Cipher::Morse => morse(input, enc),
            Cipher::Reverse => Ok(input.chars().rev().collect()),
            Cipher::Zodiac => Ok(symbol_sub(input, &ZODIAC, enc)),
            Cipher::Emoji => Ok(symbol_sub(input, &EMOJI, enc)),
            Cipher::Braille => Ok(symbol_sub(input, &BRAILLE, enc)),
            Cipher::Nato => Ok(tokens(input, enc, nato_word, nato_char)),
            Cipher::Bacon => Ok(tokens(input, enc, bacon_word, bacon_char)),
            Cipher::Invisible { cover } => invisible(input, cover, enc),
        }
    }
}

// ---------------------------------------------------------------- helpers

/// Map ASCII letters through `f` (operating on 0..26), preserving case.
fn map_letters(s: &str, f: impl Fn(i32) -> i32) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                (b'A' + f((c as u8 - b'A') as i32).rem_euclid(26) as u8) as char
            } else if c.is_ascii_lowercase() {
                (b'a' + f((c as u8 - b'a') as i32).rem_euclid(26) as u8) as char
            } else {
                c
            }
        })
        .collect()
}

fn utf8(bytes: Vec<u8>) -> CResult {
    String::from_utf8(bytes).map_err(|_| "decoded bytes are not valid UTF-8".to_string())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex input has an odd number of digits".into());
    }
    clean
        .chunks(2)
        .map(|p| {
            let s: String = p.iter().collect();
            u8::from_str_radix(&s, 16).map_err(|_| format!("invalid hex byte '{s}'"))
        })
        .collect()
}

fn key_shifts(key: &str) -> Result<Vec<i32>, String> {
    let k: Vec<i32> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c.to_ascii_uppercase() as u8 - b'A') as i32)
        .collect();
    if k.is_empty() {
        Err("key must contain at least one letter".into())
    } else {
        Ok(k)
    }
}

// ---------------------------------------------------------------- ciphers

fn caesar(s: &str, shift: i32) -> String {
    map_letters(s, |x| x + shift)
}

fn vigenere(s: &str, key: &str, enc: bool) -> CResult {
    let k = key_shifts(key)?;
    let mut i = 0;
    Ok(s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let shift = if enc { k[i % k.len()] } else { -k[i % k.len()] };
                i += 1;
                caesar(&c.to_string(), shift).chars().next().unwrap()
            } else {
                c
            }
        })
        .collect())
}

fn gcd(a: i32, b: i32) -> i32 {
    if b == 0 {
        a.abs()
    } else {
        gcd(b, a % b)
    }
}

pub const AFFINE_A_VALUES: [i32; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

fn affine(s: &str, a: i32, b: i32, enc: bool) -> CResult {
    if gcd(a.rem_euclid(26), 26) != 1 {
        return Err(format!("a={a} is not coprime with 26"));
    }
    if enc {
        Ok(map_letters(s, |x| a * x + b))
    } else {
        let inv = (1..26).find(|i| (a * i).rem_euclid(26) == 1).unwrap();
        Ok(map_letters(s, |y| inv * (y - b)))
    }
}

fn rail_pattern(len: usize, rails: usize) -> Vec<usize> {
    let cycle = 2 * (rails - 1);
    (0..len)
        .map(|i| {
            let p = i % cycle;
            if p < rails {
                p
            } else {
                cycle - p
            }
        })
        .collect()
}

fn rail_fence(s: &str, rails: usize, enc: bool) -> CResult {
    if rails < 2 {
        return Err("rail fence needs at least 2 rails".into());
    }
    let chars: Vec<char> = s.chars().collect();
    let pattern = rail_pattern(chars.len(), rails);
    let mut order: Vec<usize> = (0..chars.len()).collect();
    order.sort_by_key(|&i| (pattern[i], i));
    if enc {
        Ok(order.iter().map(|&i| chars[i]).collect())
    } else {
        let mut out = vec![' '; chars.len()];
        for (k, &i) in order.iter().enumerate() {
            out[i] = chars[k];
        }
        Ok(out.into_iter().collect())
    }
}

fn columnar(s: &str, key: &str, enc: bool) -> CResult {
    let key: Vec<char> = key.chars().filter(|c| !c.is_whitespace()).collect();
    if key.len() < 2 {
        return Err("columnar key needs at least 2 characters".into());
    }
    let n = key.len();
    let mut col_order: Vec<usize> = (0..n).collect();
    col_order.sort_by_key(|&i| (key[i].to_ascii_uppercase(), i));

    let chars: Vec<char> = s.chars().collect();
    // Grid position k sits in column k % n; read columns in key order.
    let mut order: Vec<usize> = Vec::with_capacity(chars.len());
    for &col in &col_order {
        order.extend((col..chars.len()).step_by(n));
    }
    if enc {
        Ok(order.iter().map(|&i| chars[i]).collect())
    } else {
        let mut out = vec![' '; chars.len()];
        for (k, &i) in order.iter().enumerate() {
            out[i] = chars[k];
        }
        Ok(out.into_iter().collect())
    }
}

// ---------------------------------------------------------------- enigma

pub const ROTOR_NAMES: [&str; 5] = ["I", "II", "III", "IV", "V"];
pub const REFLECTOR_NAMES: [&str; 2] = ["UKW-B", "UKW-C"];
const ROTORS: [(&str, u8); 5] = [
    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", b'Q'),
    ("AJDKSIRUXBLHWTMCQGZNPYFVOE", b'E'),
    ("BDFHJLCPRTXVZNYEIWGAKMUSQO", b'V'),
    ("ESOVPZJAYQUIRHXLNFTGKDCMWB", b'J'),
    ("VZBRGITYUPSDNHLXAWMJQOFEKC", b'Z'),
];
const REFLECTORS: [&str; 2] = ["YRUHQSLDPXNGOKMIEBFZCWVJAT", "FVPJIAOYEDRZXWGCTKUQSBNMHL"];

fn three_letters(s: &str, what: &str) -> Result<[i32; 3], String> {
    let v: Vec<i32> = s
        .trim()
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| c.is_ascii_uppercase())
        .map(|c| (c as u8 - b'A') as i32)
        .collect();
    if v.len() != 3 {
        return Err(format!("{what} must be exactly 3 letters, e.g. AAA"));
    }
    Ok([v[0], v[1], v[2]])
}

fn plugboard(s: &str) -> Result<[i32; 26], String> {
    let mut map: [i32; 26] = std::array::from_fn(|i| i as i32);
    let mut used = [false; 26];
    for pair in s.split_whitespace() {
        let p: Vec<char> = pair.chars().map(|c| c.to_ascii_uppercase()).collect();
        if p.len() != 2 || !p.iter().all(|c| c.is_ascii_uppercase()) || p[0] == p[1] {
            return Err(format!("bad plugboard pair '{pair}'"));
        }
        let (a, b) = ((p[0] as u8 - b'A') as usize, (p[1] as u8 - b'A') as usize);
        if used[a] || used[b] {
            return Err(format!("plugboard letter reused in '{pair}'"));
        }
        used[a] = true;
        used[b] = true;
        map[a] = b as i32;
        map[b] = a as i32;
    }
    Ok(map)
}

/// Enigma is self-reciprocal, so the same function encrypts and decrypts.
fn enigma(s: &str, cfg: &EnigmaConfig) -> CResult {
    if cfg.rotors.iter().any(|&r| r >= ROTORS.len()) || cfg.reflector >= REFLECTORS.len() {
        return Err("invalid rotor or reflector selection".into());
    }
    if cfg.rotors[0] == cfg.rotors[1] || cfg.rotors[1] == cfg.rotors[2] || cfg.rotors[0] == cfg.rotors[2] {
        return Err("each rotor can only be used once".into());
    }
    let mut pos = three_letters(&cfg.positions, "start positions")?;
    let rings = three_letters(&cfg.rings, "ring settings")?;
    let plug = plugboard(&cfg.plugboard)?;

    let wiring: Vec<[i32; 26]> = cfg
        .rotors
        .iter()
        .map(|&r| std::array::from_fn(|i| (ROTORS[r].0.as_bytes()[i] - b'A') as i32))
        .collect();
    let inverse: Vec<[i32; 26]> = wiring
        .iter()
        .map(|w| {
            let mut inv = [0; 26];
            for (i, &o) in w.iter().enumerate() {
                inv[o as usize] = i as i32;
            }
            inv
        })
        .collect();
    let notch: Vec<i32> = cfg.rotors.iter().map(|&r| (ROTORS[r].1 - b'A') as i32).collect();
    let refl: Vec<i32> = REFLECTORS[cfg.reflector].bytes().map(|b| (b - b'A') as i32).collect();

    let pass = |w: &[i32; 26], x: i32, p: i32, r: i32| -> i32 {
        let shift = p - r;
        (w[(x + shift).rem_euclid(26) as usize] - shift).rem_euclid(26)
    };

    Ok(s.chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            // Stepping, including the middle-rotor double step.
            if pos[1] == notch[1] {
                pos[1] = (pos[1] + 1) % 26;
                pos[0] = (pos[0] + 1) % 26;
            } else if pos[2] == notch[2] {
                pos[1] = (pos[1] + 1) % 26;
            }
            pos[2] = (pos[2] + 1) % 26;

            let lower = c.is_ascii_lowercase();
            let mut x = plug[(c.to_ascii_uppercase() as u8 - b'A') as usize];
            for i in (0..3).rev() {
                x = pass(&wiring[i], x, pos[i], rings[i]);
            }
            x = refl[x as usize];
            for i in 0..3 {
                x = pass(&inverse[i], x, pos[i], rings[i]);
            }
            x = plug[x as usize];
            let out = (b'A' + x as u8) as char;
            if lower {
                out.to_ascii_lowercase()
            } else {
                out
            }
        })
        .collect())
}

// ---------------------------------------------------------------- encodings

fn xor(s: &str, key: &str, enc: bool) -> CResult {
    if key.is_empty() {
        return Err("xor key cannot be empty".into());
    }
    let k = key.as_bytes();
    let data = if enc { s.as_bytes().to_vec() } else { from_hex(s)? };
    let out: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ k[i % k.len()]).collect();
    if enc {
        Ok(to_hex(&out))
    } else {
        utf8(out)
    }
}

fn binary(s: &str, enc: bool) -> CResult {
    if enc {
        Ok(s.as_bytes().iter().map(|b| format!("{b:08b}")).collect::<Vec<_>>().join(" "))
    } else {
        let bytes = s
            .split_whitespace()
            .map(|g| u8::from_str_radix(g, 2).map_err(|_| format!("invalid binary group '{g}'")))
            .collect::<Result<Vec<u8>, _>>()?;
        utf8(bytes)
    }
}

const MORSE: [(char, &str); 54] = [
    ('A', ".-"), ('B', "-..."), ('C', "-.-."), ('D', "-.."), ('E', "."), ('F', "..-."),
    ('G', "--."), ('H', "...."), ('I', ".."), ('J', ".---"), ('K', "-.-"), ('L', ".-.."),
    ('M', "--"), ('N', "-."), ('O', "---"), ('P', ".--."), ('Q', "--.-"), ('R', ".-."),
    ('S', "..."), ('T', "-"), ('U', "..-"), ('V', "...-"), ('W', ".--"), ('X', "-..-"),
    ('Y', "-.--"), ('Z', "--.."), ('0', "-----"), ('1', ".----"), ('2', "..---"),
    ('3', "...--"), ('4', "....-"), ('5', "....."), ('6', "-...."), ('7', "--..."),
    ('8', "---.."), ('9', "----."), ('.', ".-.-.-"), (',', "--..--"), ('?', "..--.."),
    ('\'', ".----."), ('!', "-.-.--"), ('/', "-..-."), ('(', "-.--."), (')', "-.--.-"),
    ('&', ".-..."), (':', "---..."), (';', "-.-.-."), ('=', "-...-"), ('+', ".-.-."),
    ('-', "-....-"), ('_', "..--.-"), ('"', ".-..-."), ('$', "...-..-"), ('@', ".--.-."),
];

fn morse(s: &str, enc: bool) -> CResult {
    if enc {
        let mut words = Vec::new();
        for word in s.split_whitespace() {
            let mut codes = Vec::new();
            for c in word.chars() {
                let up = c.to_ascii_uppercase();
                let code = MORSE
                    .iter()
                    .find(|(m, _)| *m == up)
                    .map(|(_, code)| *code)
                    .ok_or_else(|| format!("'{c}' has no morse code"))?;
                codes.push(code);
            }
            words.push(codes.join(" "));
        }
        Ok(words.join(" / "))
    } else {
        let mut words = Vec::new();
        for word in s.split('/') {
            let mut w = String::new();
            for code in word.split_whitespace() {
                let ch = MORSE
                    .iter()
                    .find(|(_, m)| *m == code)
                    .map(|(c, _)| *c)
                    .ok_or_else(|| format!("unknown morse sequence '{code}'"))?;
                w.push(ch);
            }
            if !w.is_empty() {
                words.push(w);
            }
        }
        Ok(words.join(" "))
    }
}

// ---------------------------------------------------------------- fun

impl Cipher {
    /// Whether decrypting gives back UPPERCASE text rather than the original case.
    #[cfg(test)]
    pub fn loses_case(&self) -> bool {
        matches!(
            self,
            Cipher::Morse | Cipher::Zodiac | Cipher::Emoji | Cipher::Braille | Cipher::Nato | Cipher::Bacon
        )
    }
}

const ZODIAC: [char; 26] = [
    '♈', '♉', '♊', '♋', '♌', '♍', '♎', '♏', '♐', '♑', '♒', '♓', '☉', '☽', '☿', '♀', '♁',
    '♂', '♃', '♄', '♅', '♆', '♇', '☊', '☋', '⚸',
];
const EMOJI: [char; 26] = [
    '🍎', '🍌', '🐱', '🐶', '🐘', '🐸', '🍇', '🏠', '🍦', '🃏', '🔑', '🍋', '🌙', '🎵', '🐙',
    '🐧', '👑', '🌈', '⭐', '🌴', '🌂', '🎻', '🌊', '❌', '⚡', '🍕',
];
const BRAILLE: [char; 26] = [
    '⠁', '⠃', '⠉', '⠙', '⠑', '⠋', '⠛', '⠓', '⠊', '⠚', '⠅', '⠇', '⠍', '⠝', '⠕', '⠏', '⠟',
    '⠗', '⠎', '⠞', '⠥', '⠧', '⠺', '⠭', '⠽', '⠵',
];

/// Swap letters for symbols (case-insensitive); everything else passes through.
fn symbol_sub(s: &str, table: &[char; 26], enc: bool) -> String {
    s.chars()
        .filter(|&c| c != '\u{FE0F}') // emoji variation selector added by some apps
        .map(|c| {
            if enc {
                if c.is_ascii_alphabetic() {
                    table[(c.to_ascii_uppercase() as u8 - b'A') as usize]
                } else {
                    c
                }
            } else {
                match table.iter().position(|&t| t == c) {
                    Some(i) => (b'A' + i as u8) as char,
                    None => c,
                }
            }
        })
        .collect()
}

const NATO: [&str; 36] = [
    "Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliett",
    "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
    "Uniform", "Victor", "Whiskey", "Xray", "Yankee", "Zulu", "Zero", "One", "Two", "Three",
    "Four", "Five", "Six", "Seven", "Eight", "Nine",
];

fn nato_word(c: char) -> Option<String> {
    let i = match c.to_ascii_uppercase() {
        u @ 'A'..='Z' => (u as u8 - b'A') as usize,
        d @ '0'..='9' => 26 + (d as u8 - b'0') as usize,
        _ => return None,
    };
    Some(NATO[i].to_string())
}

fn nato_char(tok: &str) -> Option<char> {
    let i = NATO.iter().position(|w| w.eq_ignore_ascii_case(tok))?;
    Some(if i < 26 { (b'A' + i as u8) as char } else { (b'0' + (i - 26) as u8) as char })
}

fn bacon_word(c: char) -> Option<String> {
    if !c.is_ascii_alphabetic() {
        return None;
    }
    let i = c.to_ascii_uppercase() as u8 - b'A';
    Some((0..5).rev().map(|b| if i >> b & 1 == 1 { 'B' } else { 'A' }).collect())
}

fn bacon_char(tok: &str) -> Option<char> {
    let t = tok.to_ascii_uppercase();
    if t.len() != 5 || !t.chars().all(|c| c == 'A' || c == 'B') {
        return None;
    }
    let i = t.chars().fold(0u8, |acc, c| acc << 1 | (c == 'B') as u8);
    (i < 26).then(|| (b'A' + i) as char)
}

/// Token codecs: one token per character, words separated by " / ".
/// Characters without a code are kept as literal tokens.
fn tokens(
    s: &str,
    enc: bool,
    word: fn(char) -> Option<String>,
    unword: fn(&str) -> Option<char>,
) -> String {
    if enc {
        s.split_whitespace()
            .map(|w| {
                w.chars()
                    .map(|c| word(c).unwrap_or_else(|| c.to_string()))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join(" / ")
    } else {
        s.split('/')
            .map(|w| {
                w.split_whitespace()
                    .map(|t| unword(t).map(String::from).unwrap_or_else(|| t.to_string()))
                    .collect::<String>()
            })
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

const ZW0: char = '\u{200B}'; // zero-width space      = bit 0
const ZW1: char = '\u{200C}'; // zero-width non-joiner = bit 1

fn invisible(s: &str, cover: &str, enc: bool) -> CResult {
    if enc {
        let hidden: String = s
            .bytes()
            .flat_map(|b| (0..8).rev().map(move |i| if b >> i & 1 == 1 { ZW1 } else { ZW0 }))
            .collect();
        // Tuck the hidden bits in after the cover's first character.
        let mut chars = cover.chars();
        Ok(match chars.next() {
            Some(first) => format!("{first}{hidden}{}", chars.as_str()),
            None => hidden,
        })
    } else {
        let bits: Vec<u8> = s
            .chars()
            .filter_map(|c| match c {
                ZW0 => Some(0),
                ZW1 => Some(1),
                _ => None,
            })
            .collect();
        if bits.is_empty() {
            return Err("no hidden message found".into());
        }
        if bits.len() % 8 != 0 {
            return Err("hidden message is damaged (incomplete byte)".into());
        }
        utf8(bits.chunks(8).map(|ch| ch.iter().fold(0u8, |a, &b| a << 1 | b)).collect())
    }
}

// ---------------------------------------------------------------- pipeline

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub cipher: Cipher,
    pub enabled: bool,
}

pub struct TraceEntry {
    /// Index of the step in the pipeline list.
    pub index: usize,
    pub name: &'static str,
    pub result: CResult,
}

/// Run the enabled steps. Encrypt goes top-to-bottom; decrypt undoes them
/// bottom-to-top. Stops at the first failing step.
pub fn run_pipeline(steps: &[Step], input: &str, mode: Mode) -> Vec<TraceEntry> {
    let mut order: Vec<usize> = (0..steps.len()).filter(|&i| steps[i].enabled).collect();
    if mode == Mode::Decrypt {
        order.reverse();
    }
    let mut trace = Vec::new();
    let mut current = input.to_string();
    for i in order {
        let result = steps[i].cipher.apply(&current, mode);
        let failed = result.is_err();
        if let Ok(ref s) = result {
            current = s.clone();
        }
        trace.push(TraceEntry { index: i, name: steps[i].cipher.name(), result });
        if failed {
            break;
        }
    }
    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Attack at Dawn! Meet @ 0600, bring 3 maps.";

    fn roundtrip(c: Cipher) {
        let enc = c.apply(SAMPLE, Mode::Encrypt).unwrap();
        let dec = c.apply(&enc, Mode::Decrypt).unwrap();
        if c.loses_case() {
            assert_eq!(dec, SAMPLE.to_uppercase(), "{}", c.name());
        } else {
            assert_eq!(dec, SAMPLE, "{}", c.name());
            if !matches!(c, Cipher::Reverse) {
                assert_ne!(enc, SAMPLE, "{} should change the text", c.name());
            }
        }
    }

    #[test]
    fn all_ciphers_roundtrip() {
        for c in Cipher::catalog() {
            roundtrip(c);
        }
    }

    #[test]
    fn known_vectors() {
        let e = |c: Cipher, s: &str| c.apply(s, Mode::Encrypt).unwrap();
        assert_eq!(e(Cipher::Caesar { shift: 3 }, "HELLO"), "KHOOR");
        assert_eq!(e(Cipher::Vigenere { key: "LEMON".into() }, "ATTACKATDAWN"), "LXFOPVEFRNHR");
        assert_eq!(e(Cipher::Atbash, "abc"), "zyx");
        assert_eq!(e(Cipher::Affine { a: 5, b: 8 }, "AFFINECIPHER"), "IHHWVCSWFRCP");
        assert_eq!(e(Cipher::RailFence { rails: 3 }, "WEAREDISCOVEREDFLEEATONCE"), "WECRLTEERDSOEEFEAOCAIVDEN");
        assert_eq!(e(Cipher::Enigma(EnigmaConfig::default()), "AAAAA"), "BDZGO");
        assert_eq!(e(Cipher::Base64, "hi"), "aGk=");
        assert_eq!(e(Cipher::Morse, "sos"), "... --- ...");
        assert_eq!(e(Cipher::Nato, "Hi 5"), "Hotel India / Five");
        assert_eq!(e(Cipher::Bacon, "AbZ"), "AAAAA AAAAB BBAAB");
        assert_eq!(e(Cipher::Emoji, "ab!"), "🍎🍌!");
        assert_eq!(e(Cipher::Braille, "hi"), "⠓⠊");
        let hidden = e(Cipher::Invisible { cover: "hey".into() }, "x");
        assert!(hidden.starts_with('h') && hidden.ends_with("ey"));
        assert_eq!(hidden.chars().count(), 3 + 8);
    }

    #[test]
    fn enigma_full_config_roundtrip() {
        // Start at ADU so the middle-rotor double step is exercised.
        let cfg = EnigmaConfig { positions: "ADU".into(), ..Default::default() };
        let c = Cipher::Enigma(cfg);
        let long = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG".repeat(30);
        let enc = c.apply(&long, Mode::Encrypt).unwrap();
        assert!(enc.chars().zip(long.chars()).all(|(a, b)| a != b), "enigma never maps a letter to itself");
        assert_eq!(c.apply(&enc, Mode::Decrypt).unwrap(), long);

        let cfg = EnigmaConfig {
            rotors: [4, 2, 0],
            reflector: 1,
            positions: "QEV".into(),
            rings: "BUL".into(),
            plugboard: "AQ BJ CW DS".into(),
        };
        let c = Cipher::Enigma(cfg);
        let enc = c.apply("Hello World", Mode::Encrypt).unwrap();
        assert_eq!(c.apply(&enc, Mode::Decrypt).unwrap(), "Hello World");
    }

    #[test]
    fn pipeline_roundtrip() {
        let steps: Vec<Step> = Cipher::catalog()
            .into_iter()
            .filter(|c| !c.loses_case())
            .map(|cipher| Step { cipher, enabled: true })
            .collect();
        let enc = run_pipeline(&steps, SAMPLE, Mode::Encrypt);
        let out = enc.last().unwrap().result.clone().unwrap();
        let dec = run_pipeline(&steps, &out, Mode::Decrypt);
        assert_eq!(dec.last().unwrap().result.clone().unwrap(), SAMPLE);
    }
}
