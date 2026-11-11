use crate::ciphers::{
    run_pipeline, Cipher, EnigmaConfig, Mode, Step, TraceEntry, AFFINE_A_VALUES, REFLECTOR_NAMES,
    ROTOR_NAMES,
};
use crate::envelope::{self, Recipe};
use crate::theme::*;
use eframe::egui::{
    self, Align, Button, Frame, Layout, Margin, RichText, Rounding, ScrollArea, Slider, Stroke,
    TextEdit, TextStyle,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// What gets written to disk between runs (never the message text).
#[derive(Serialize, Deserialize)]
struct Saved {
    steps: Vec<Step>,
    mode: Mode,
}

/// A failure to show in the output box and status bar.
struct RunError {
    title: String,
    msg: String,
    /// Pipeline card to highlight (only when our own pipeline failed).
    step: Option<usize>,
}

/// Everything derived from the current input each frame.
struct RunResult {
    trace: Vec<TraceEntry>,
    output: String,
    error: Option<RunError>,
    /// Steps from a pasted sealed message, if the input is one.
    sealed: Option<Vec<Step>>,
    effective_mode: Mode,
    steps_run: usize,
}

enum StepAction {
    Up(usize),
    Down(usize),
    Duplicate(usize),
    Remove(usize),
}

pub struct CipherApp {
    steps: Vec<Step>,
    mode: Mode,
    embed_key: bool,
    input: String,
    show_import: bool,
    import_text: String,
    import_error: Option<String>,
    toast: Option<(String, f64)>,
}

impl CipherApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        let saved: Option<Saved> = cc.storage.and_then(|s| eframe::get_value(s, eframe::APP_KEY));
        let (steps, mode) = match saved {
            Some(s) => (s.steps, s.mode),
            None => (
                vec![
                    Step { cipher: Cipher::Enigma(EnigmaConfig::default()), enabled: true },
                    Step { cipher: Cipher::Vigenere { key: "LEMON".into() }, enabled: true },
                    Step { cipher: Cipher::Base64, enabled: true },
                ],
                Mode::Encrypt,
            ),
        };
        Self {
            steps,
            mode,
            // Off on every launch: the key is only included when asked for.
            embed_key: false,
            input: "Attack at dawn. Bring the maps.".into(),
            show_import: false,
            import_text: String::new(),
            import_error: None,
            toast: None,
        }
    }

    fn notify(&mut self, ctx: &egui::Context, msg: impl Into<String>) {
        self.toast = Some((msg.into(), ctx.input(|i| i.time)));
    }

    /// Run the input through either the pipeline or, for a pasted sealed
    /// message, the recipe embedded in it.
    fn run(&self) -> RunResult {
        let (steps, body, mode, sealed) = match envelope::open(&self.input) {
            Some(Err(msg)) => {
                return RunResult {
                    trace: vec![],
                    output: String::new(),
                    error: Some(RunError { title: "sealed message".into(), msg, step: None }),
                    sealed: None,
                    effective_mode: Mode::Decrypt,
                    steps_run: 0,
                }
            }
            Some(Ok((steps, body))) => (steps.clone(), body, Mode::Decrypt, Some(steps)),
            None => (self.steps.clone(), self.input.clone(), self.mode, None),
        };
        let trace = run_pipeline(&steps, &body, mode);
        let error = trace.iter().find_map(|t| {
            t.result.as_ref().err().map(|e| RunError {
                title: format!("step {:02} ({})", t.index + 1, t.name),
                msg: e.clone(),
                step: if sealed.is_none() { Some(t.index) } else { None },
            })
        });
        let mut output = match trace.last() {
            None => body.clone(),
            Some(t) => t.result.clone().unwrap_or_default(),
        };
        if mode == Mode::Encrypt && self.embed_key && error.is_none() && !trace.is_empty() {
            output = envelope::seal(&steps, &output);
        }
        RunResult {
            steps_run: steps.iter().filter(|s| s.enabled).count(),
            trace,
            output,
            error,
            sealed,
            effective_mode: mode,
        }
    }
}

const EMBED_HELP: &str = "wrap the output with the settings needed to decrypt it,\n\
     so it can be pasted straight back in to decrypt.\n\
     note: anyone who has the message can then read it.";

fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Encrypt => "encrypt",
        Mode::Decrypt => "decrypt",
    }
}

fn copy(ctx: &egui::Context, text: String) {
    ctx.output_mut(|o| o.copied_text = text);
}

fn small_btn(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(Button::new(RichText::new(text).color(GREEN)).small())
}

fn section_title(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(format!("┌─ {title}")).color(GREEN_DIM).strong());
}

fn field_frame() -> Frame {
    Frame::none()
        .fill(FIELD)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::same(10.0))
}

fn labeled<R>(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.horizontal(|ui| {
        ui.add_sized([78.0, 20.0], egui::Label::new(RichText::new(label).color(MUTED)));
        add(ui)
    })
    .inner
}

fn text_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    labeled(ui, label, |ui| {
        ui.add(
            TextEdit::singleline(value)
                .hint_text(hint)
                .font(TextStyle::Monospace)
                .desired_width(f32::INFINITY),
        );
    });
}

/// Parameter editor for a single cipher step.
fn cipher_params(ui: &mut egui::Ui, id: usize, cipher: &mut Cipher) {
    match cipher {
        Cipher::Caesar { shift } => {
            labeled(ui, "shift", |ui| ui.add(Slider::new(shift, -25..=25).trailing_fill(true)));
        }
        Cipher::Vigenere { key } => text_field(ui, "key", key, "letters only"),
        Cipher::Columnar { key } => text_field(ui, "key", key, "e.g. ZEBRA"),
        Cipher::Xor { key } => text_field(ui, "key", key, "any text"),
        Cipher::Invisible { cover } => text_field(ui, "cover", cover, "visible decoy text"),
        Cipher::Affine { a, b } => {
            labeled(ui, "a", |ui| {
                egui::ComboBox::new(("affine-a", id), "")
                    .width(60.0)
                    .selected_text(a.to_string())
                    .show_ui(ui, |ui| {
                        for v in AFFINE_A_VALUES {
                            ui.selectable_value(a, v, v.to_string());
                        }
                    });
            });
            labeled(ui, "b", |ui| ui.add(Slider::new(b, 0..=25).trailing_fill(true)));
        }
        Cipher::RailFence { rails } => {
            labeled(ui, "rails", |ui| ui.add(Slider::new(rails, 2..=12).trailing_fill(true)));
        }
        Cipher::Enigma(cfg) => {
            labeled(ui, "rotors", |ui| {
                for (k, slot) in ["L", "M", "R"].iter().enumerate() {
                    egui::ComboBox::new(("rotor", id, k), "")
                        .width(52.0)
                        .selected_text(ROTOR_NAMES[cfg.rotors[k]])
                        .show_ui(ui, |ui| {
                            for (i, n) in ROTOR_NAMES.iter().enumerate() {
                                ui.selectable_value(&mut cfg.rotors[k], i, *n);
                            }
                        })
                        .response
                        .on_hover_text(format!("{slot} rotor"));
                }
            });
            labeled(ui, "reflector", |ui| {
                egui::ComboBox::new(("reflector", id), "")
                    .width(80.0)
                    .selected_text(REFLECTOR_NAMES[cfg.reflector])
                    .show_ui(ui, |ui| {
                        for (i, n) in REFLECTOR_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut cfg.reflector, i, *n);
                        }
                    });
            });
            text_field(ui, "start pos", &mut cfg.positions, "AAA");
            text_field(ui, "rings", &mut cfg.rings, "AAA");
            text_field(ui, "plugboard", &mut cfg.plugboard, "AB CD EF ...");
        }
        Cipher::Rot13
        | Cipher::Atbash
        | Cipher::Base64
        | Cipher::Hex
        | Cipher::Binary
        | Cipher::Morse
        | Cipher::Reverse
        | Cipher::Zodiac
        | Cipher::Emoji
        | Cipher::Braille
        | Cipher::Nato
        | Cipher::Bacon => {
            ui.label(RichText::new(cipher.description()).color(MUTED).small());
        }
    }
}

impl eframe::App for CipherApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(
            storage,
            eframe::APP_KEY,
            &Saved { steps: self.steps.clone(), mode: self.mode },
        );
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|i| i.time);
        let run = self.run();

        self.top_bar(ctx, now);
        self.status_bar(ctx, now, &run);
        self.pipeline_panel(ctx, run.error.as_ref().and_then(|e| e.step));
        self.io_panel(ctx, &run);
        self.import_window(ctx);

        // Keep the cursor blinking.
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl CipherApp {
    fn top_bar(&mut self, ctx: &egui::Context, now: f64) {
        egui::TopBottomPanel::top("top")
            .frame(Frame::none().fill(BG).inner_margin(Margin::symmetric(14.0, 10.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(RichText::new("root@cipherterm").color(GREEN).strong());
                    ui.label(RichText::new(":").color(TEXT));
                    ui.label(RichText::new("~/vault").color(CYAN));
                    ui.label(RichText::new("$ ").color(TEXT));
                    ui.label(
                        RichText::new(format!("./cipher --{}", mode_word(self.mode))).color(TEXT),
                    );
                    let blink = (now * 2.0) as i64 % 2 == 0;
                    ui.label(RichText::new(if blink { " █" } else { "  " }).color(GREEN));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        if small_btn(ui, "import recipe").clicked() {
                            self.show_import = true;
                            self.import_error = None;
                        }
                        if small_btn(ui, "export recipe")
                            .on_hover_text("copy this pipeline as JSON so someone else can decrypt")
                            .clicked()
                        {
                            let recipe = Recipe { cipherterm: 1, steps: self.steps.clone() };
                            copy(ctx, serde_json::to_string_pretty(&recipe).unwrap_or_default());
                            self.notify(ctx, "recipe copied to clipboard");
                        }
                        ui.add_space(16.0);
                        for (m, label) in [(Mode::Decrypt, " DECRYPT "), (Mode::Encrypt, " ENCRYPT ")] {
                            let selected = self.mode == m;
                            let color = if selected {
                                if m == Mode::Encrypt { GREEN } else { AMBER }
                            } else {
                                MUTED
                            };
                            if ui
                                .selectable_label(selected, RichText::new(label).color(color).strong())
                                .clicked()
                            {
                                self.mode = m;
                            }
                        }
                    });
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context, now: f64, run: &RunResult) {
        if let Some((_, t)) = &self.toast {
            if now - t > 2.5 {
                self.toast = None;
            }
        }
        egui::TopBottomPanel::bottom("status")
            .frame(Frame::none().fill(BG).inner_margin(Margin::symmetric(14.0, 6.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    match &run.error {
                        None => ui.label(RichText::new("[ OK ]").color(GREEN).strong()),
                        Some(e) => ui.label(
                            RichText::new(format!("[ ERR {} ]", e.title)).color(RED).strong(),
                        ),
                    };
                    if run.sealed.is_some() {
                        ui.label(RichText::new("[ SEALED ]").color(AMBER).strong());
                    }
                    let stat = |ui: &mut egui::Ui, k: &str, v: String| {
                        ui.label(RichText::new(k).color(MUTED));
                        ui.label(RichText::new(v).color(TEXT));
                    };
                    stat(ui, "in", self.input.chars().count().to_string());
                    stat(ui, "out", run.output.chars().count().to_string());
                    stat(ui, "steps", run.steps_run.to_string());
                    stat(ui, "mode", mode_word(run.effective_mode).to_string());
                    if let Some((msg, _)) = &self.toast {
                        ui.label(RichText::new(format!(">> {msg}")).color(CYAN));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(concat!("cipherterm v", env!("CARGO_PKG_VERSION")))
                                .color(MUTED)
                                .small(),
                        );
                    });
                });
            });
    }

    fn pipeline_panel(&mut self, ctx: &egui::Context, err_index: Option<usize>) {
        egui::SidePanel::left("pipeline")
            .resizable(true)
            .default_width(390.0)
            .min_width(320.0)
            .frame(
                Frame::none()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .inner_margin(Margin::same(14.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    section_title(ui, "PIPELINE");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.menu_button(RichText::new("+ add step").color(GREEN).strong(), |ui| {
                            ui.set_min_width(430.0);
                            for c in Cipher::catalog() {
                                let text = RichText::new(format!("{:<11} {}", c.name(), c.description()));
                                if ui.button(text).clicked() {
                                    self.steps.push(Step { cipher: c, enabled: true });
                                    ui.close_menu();
                                }
                            }
                        });
                        if !self.steps.is_empty() && small_btn(ui, "clear").clicked() {
                            self.steps.clear();
                        }
                    });
                });
                let hint = match self.mode {
                    Mode::Encrypt => "│ encrypt runs top ↓ bottom",
                    Mode::Decrypt => "│ decrypt undoes steps bottom ↑ top",
                };
                ui.label(RichText::new(hint).color(MUTED).small());
                ui.add_space(4.0);

                let mut action = None;
                let len = self.steps.len();
                ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    if self.steps.is_empty() {
                        ui.add_space(30.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("pipeline empty").color(MUTED));
                            ui.label(
                                RichText::new("use [+ add step] to chain ciphers").color(MUTED).small(),
                            );
                        });
                    }
                    for (i, step) in self.steps.iter_mut().enumerate() {
                        if i > 0 {
                            ui.label(RichText::new("   │").color(BORDER));
                        }
                        let border = if err_index == Some(i) {
                            RED
                        } else if step.enabled {
                            BORDER
                        } else {
                            dim(BORDER)
                        };
                        Frame::none()
                            .fill(CARD)
                            .stroke(Stroke::new(1.0_f32, border))
                            .rounding(Rounding::same(7.0))
                            .inner_margin(Margin::same(10.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{:02}", i + 1)).color(MUTED));
                                    ui.checkbox(&mut step.enabled, "")
                                        .on_hover_text("enable / bypass this step");
                                    let name_color = if step.enabled { GREEN } else { MUTED };
                                    ui.label(
                                        RichText::new(step.cipher.name()).color(name_color).strong(),
                                    )
                                    .on_hover_text(step.cipher.description());
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.spacing_mut().item_spacing.x = 4.0;
                                        if small_btn(ui, "x").on_hover_text("remove").clicked() {
                                            action = Some(StepAction::Remove(i));
                                        }
                                        if small_btn(ui, "+").on_hover_text("duplicate").clicked() {
                                            action = Some(StepAction::Duplicate(i));
                                        }
                                        if i + 1 < len
                                            && small_btn(ui, "v").on_hover_text("move down").clicked()
                                        {
                                            action = Some(StepAction::Down(i));
                                        }
                                        if i > 0 && small_btn(ui, "^").on_hover_text("move up").clicked() {
                                            action = Some(StepAction::Up(i));
                                        }
                                    });
                                });
                                if step.enabled {
                                    ui.add_space(2.0);
                                    cipher_params(ui, i, &mut step.cipher);
                                }
                            });
                    }
                });

                match action {
                    Some(StepAction::Up(i)) => self.steps.swap(i, i - 1),
                    Some(StepAction::Down(i)) => self.steps.swap(i, i + 1),
                    Some(StepAction::Duplicate(i)) => {
                        let s = self.steps[i].clone();
                        self.steps.insert(i + 1, s);
                    }
                    Some(StepAction::Remove(i)) => {
                        self.steps.remove(i);
                    }
                    None => {}
                }
            });
    }

    fn io_panel(&mut self, ctx: &egui::Context, run: &RunResult) {
        let trace: &[TraceEntry] = &run.trace;
        let error = &run.error;
        let output = run.output.as_str();
        let mode = run.effective_mode;
        egui::CentralPanel::default()
            .frame(Frame::none().fill(BG).inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| {
                let row_h = ui.text_style_height(&TextStyle::Monospace);
                let banner_h = if run.sealed.is_some() { 40.0 } else { 0.0 };
                let box_h = ((ui.available_height() - 190.0 - banner_h) / 2.0).max(90.0);
                let rows = ((box_h - 20.0) / row_h).max(3.0) as usize;

                // ---- input
                ui.horizontal(|ui| {
                    let label = match mode {
                        Mode::Decrypt if run.sealed.is_some() => "STDIN · sealed message",
                        Mode::Encrypt => "STDIN · plaintext",
                        Mode::Decrypt => "STDIN · ciphertext",
                    };
                    section_title(ui, label);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_btn(ui, "clear").clicked() {
                            self.input.clear();
                        }
                    });
                });
                field_frame().show(ui, |ui| {
                    ui.push_id("input", |ui| {
                        ScrollArea::vertical().max_height(box_h).auto_shrink([false, true]).show(
                            ui,
                            |ui| {
                                ui.add(
                                    TextEdit::multiline(&mut self.input)
                                        .frame(false)
                                        .font(TextStyle::Monospace)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(rows)
                                        .hint_text("type or paste a message..."),
                                );
                            },
                        );
                    });
                });

                // ---- sealed message banner
                if let Some(steps) = &run.sealed {
                    ui.add_space(4.0);
                    Frame::none()
                        .fill(egui::Color32::from_rgb(40, 32, 8))
                        .stroke(Stroke::new(1.0_f32, AMBER))
                        .rounding(Rounding::same(6.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "◆ sealed message: decrypting with its embedded key ({} step(s))",
                                        steps.len()
                                    ))
                                    .color(AMBER),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if small_btn(ui, "load key into pipeline")
                                        .on_hover_text("replace your pipeline with the one in this message")
                                        .clicked()
                                    {
                                        self.steps = steps.clone();
                                        self.notify(ctx, "embedded key loaded into pipeline");
                                    }
                                });
                            });
                        });
                }

                // ---- flow indicator
                ui.add_space(4.0);
                let enabled = run.steps_run;
                let (arrow_color, verb) = match mode {
                    Mode::Encrypt => (GREEN, "encrypting"),
                    Mode::Decrypt => (AMBER, "decrypting"),
                };
                ui.label(
                    RichText::new(format!("  │\n  ▼  {verb} through {enabled} step(s)"))
                        .color(arrow_color),
                );
                ui.add_space(4.0);

                // ---- output
                ui.horizontal(|ui| {
                    let label = match mode {
                        Mode::Encrypt if self.embed_key => "STDOUT · sealed message",
                        Mode::Encrypt => "STDOUT · ciphertext",
                        Mode::Decrypt => "STDOUT · plaintext",
                    };
                    section_title(ui, label);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_btn(ui, "swap ⇅")
                            .on_hover_text("move output to input and flip encrypt/decrypt")
                            .clicked()
                            && error.is_none()
                        {
                            self.input = output.to_string();
                            self.mode = match mode {
                                Mode::Encrypt => Mode::Decrypt,
                                Mode::Decrypt => Mode::Encrypt,
                            };
                        }
                        if small_btn(ui, "copy").clicked() && error.is_none() {
                            copy(ctx, output.to_string());
                            self.notify(ctx, "output copied to clipboard");
                        }
                        if mode == Mode::Encrypt {
                            ui.checkbox(&mut self.embed_key, RichText::new("embed key").color(AMBER))
                                .on_hover_text(EMBED_HELP);
                        }
                    });
                });
                let out_frame = match error {
                    Some(_) => field_frame().stroke(Stroke::new(1.0_f32, RED)),
                    None => field_frame(),
                };
                out_frame.show(ui, |ui| {
                    ui.push_id("output", |ui| {
                        ScrollArea::vertical().max_height(box_h).auto_shrink([false, true]).show(
                            ui,
                            |ui| match error {
                                Some(e) => {
                                    ui.set_min_height(box_h - 20.0);
                                    ui.label(
                                        RichText::new(format!("error: {} failed\n  -> {}", e.title, e.msg))
                                            .color(RED),
                                    );
                                }
                                None => {
                                    let mut text = output;
                                    ui.add(
                                        TextEdit::multiline(&mut text)
                                            .frame(false)
                                            .font(TextStyle::Monospace)
                                            .text_color(GREEN)
                                            .desired_width(f32::INFINITY)
                                            .desired_rows(rows),
                                    );
                                }
                            },
                        );
                    });
                });

                // ---- trace
                ui.add_space(8.0);
                egui::CollapsingHeader::new(RichText::new("trace · intermediate output").color(MUTED))
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.push_id("trace", |ui| {
                            ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                                if trace.is_empty() {
                                    ui.label(RichText::new("no enabled steps").color(MUTED));
                                }
                                for t in trace {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format!("[{:02}] {:<10}", t.index + 1, t.name))
                                                .color(CYAN),
                                        );
                                        match &t.result {
                                            Ok(s) => {
                                                let short: String = s.chars().take(160).collect();
                                                let more = if s.chars().count() > 160 { "…" } else { "" };
                                                ui.label(RichText::new(format!("{short}{more}")).color(TEXT));
                                            }
                                            Err(e) => {
                                                ui.label(RichText::new(e).color(RED));
                                            }
                                        }
                                    });
                                }
                            });
                        });
                    });
            });
    }

    fn import_window(&mut self, ctx: &egui::Context) {
        if !self.show_import {
            return;
        }
        let mut open = true;
        let mut loaded = false;
        egui::Window::new(RichText::new("import recipe").color(GREEN).strong())
            .open(&mut open)
            .collapsible(false)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("paste a recipe exported with [export recipe]").color(MUTED),
                );
                ui.push_id("import", |ui| {
                    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut self.import_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(12),
                        );
                    });
                });
                if let Some(e) = &self.import_error {
                    ui.label(RichText::new(format!("error: {e}")).color(RED));
                }
                ui.horizontal(|ui| {
                    if small_btn(ui, "load").clicked() {
                        match serde_json::from_str::<Recipe>(&self.import_text) {
                            Ok(r) => {
                                self.steps = r.steps;
                                loaded = true;
                            }
                            Err(e) => self.import_error = Some(e.to_string()),
                        }
                    }
                });
            });
        if loaded {
            self.import_text.clear();
            self.notify(ctx, "recipe loaded");
        }
        if !open || loaded {
            self.show_import = false;
        }
    }
}

/// Darker border for bypassed steps.
fn dim(c: egui::Color32) -> egui::Color32 {
    egui::Color32::from_rgb(c.r() / 2, c.g() / 2, c.b() / 2)
}
