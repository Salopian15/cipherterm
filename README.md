# cipherterm

A terminal-styled desktop app (Rust + egui) for layering classic ciphers and encodings.
Runs on Windows, macOS and Linux.

## Features

- **Pipeline**: chain any number of steps. Reorder, duplicate, bypass or remove them.
  Encrypt runs top to bottom; decrypt undoes the steps bottom to top.
- **Ciphers**: Caesar, ROT13, Atbash, Vigenère, Affine, Rail Fence, Columnar transposition,
  Enigma M3 (rotors I–V, UKW-B/C, ring settings, start positions, plugboard), repeating-key XOR.
- **Encodings**: Base64, Hex, Binary, Morse, Reverse.
- **Fun alphabets**: Zodiac (♈♉♊…), Emoji (🍎🍌🐱…), Braille, NATO phonetic, Bacon's cipher,
  and Invisible (hides the message as zero-width characters inside a harmless cover sentence).
  Symbol sets use your OS symbol font (Segoe UI Symbol / Apple Symbols / DejaVu Sans) when present.
- **Sealed messages** (`embed key`, off by default): the output becomes one plain block of text that holds
  both the ciphertext and the settings needed to decrypt it, e.g.

  ```
  eyJjaXBoZXJ0ZXJtIjoxLCJzdGVwcyI6W3sidHlwZSI6IlZpZ2VuZXJlIiwia2V5
  IjoiTEVNT04ifV0sImJvZHkiOiJMeGZvcHYgZWYgcm5ociJ9...
  ```

  Paste it into the input and it decrypts on its own, whatever the current pipeline is.
  *Anyone who has a sealed message can read it.* Turn `embed key` off and share the recipe
  separately (`export recipe` / `import recipe`) if you want the key kept apart.
- **Trace**: shows the output after each step, and errors point to the step that failed.
- Your pipeline is saved between runs. Message text is never saved.

## Build

Install Rust from https://rustup.rs, then:

```bash
cargo run --release
```

The binary ends up in `target/release/`.

- **Linux** needs the usual GUI dev packages, e.g. on Debian/Ubuntu:
  `sudo apt install libxkbcommon-dev libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libwayland-dev`
- **macOS**: needs Xcode command line tools (`xcode-select --install`).
- **Windows (GNU toolchain)**: put a MinGW-w64 `bin` folder (e.g. WinLibs) on `PATH`.
  If the project sits in a very long path, set `CARGO_TARGET_DIR` to a short folder.

## Tests

```bash
cargo test
```

The tests round-trip every cipher, check known test vectors (including the historical
Enigma `AAAAA → BDZGO`), and seal/unseal a multi-step message.
