//! Dark, phosphor-green terminal theme.

use eframe::egui::{
    self, Color32, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals,
};

pub const BG: Color32 = Color32::from_rgb(8, 11, 9);
pub const PANEL: Color32 = Color32::from_rgb(12, 17, 14);
pub const CARD: Color32 = Color32::from_rgb(17, 24, 20);
pub const FIELD: Color32 = Color32::from_rgb(5, 8, 6);
pub const BORDER: Color32 = Color32::from_rgb(30, 54, 40);
pub const GREEN: Color32 = Color32::from_rgb(57, 255, 136);
pub const GREEN_DIM: Color32 = Color32::from_rgb(34, 140, 82);
pub const AMBER: Color32 = Color32::from_rgb(255, 184, 0);
pub const CYAN: Color32 = Color32::from_rgb(80, 220, 230);
pub const RED: Color32 = Color32::from_rgb(255, 85, 102);
pub const TEXT: Color32 = Color32::from_rgb(196, 240, 210);
pub const MUTED: Color32 = Color32::from_rgb(92, 124, 104);

/// System fonts with broad symbol coverage (zodiac, braille, zero-width...).
/// The first one found on each OS is added as a fallback after the built-in fonts.
const SYMBOL_FONTS: &[&str] = &[
    // Windows
    "C:\\Windows\\Fonts\\seguisym.ttf",
    // macOS
    "/System/Library/Fonts/Apple Symbols.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    // Linux
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf",
    "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf",
];

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Some(bytes) = SYMBOL_FONTS.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert("symbols".into(), egui::FontData::from_owned(bytes));
        for family in [FontFamily::Monospace, FontFamily::Proportional] {
            fonts.families.entry(family).or_default().push("symbols".into());
        }
    }
    ctx.set_fonts(fonts);
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    let mut v = Visuals::dark();
    v.override_text_color = Some(TEXT);
    v.panel_fill = PANEL;
    v.window_fill = CARD;
    v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.window_rounding = Rounding::same(8.0);
    v.extreme_bg_color = FIELD;
    v.faint_bg_color = CARD;
    v.code_bg_color = FIELD;
    v.hyperlink_color = CYAN;
    v.selection.bg_fill = Color32::from_rgb(24, 92, 56);
    v.selection.stroke = Stroke::new(1.0_f32, GREEN);
    v.text_cursor.stroke = Stroke::new(2.0_f32, GREEN);
    v.error_fg_color = RED;
    v.warn_fg_color = AMBER;

    let r = Rounding::same(5.0);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = CARD;
    w.noninteractive.weak_bg_fill = CARD;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.noninteractive.rounding = r;

    w.inactive.bg_fill = Color32::from_rgb(20, 32, 25);
    w.inactive.weak_bg_fill = Color32::from_rgb(20, 32, 25);
    w.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.inactive.rounding = r;

    w.hovered.bg_fill = Color32::from_rgb(26, 48, 35);
    w.hovered.weak_bg_fill = Color32::from_rgb(26, 48, 35);
    w.hovered.bg_stroke = Stroke::new(1.0_f32, GREEN_DIM);
    w.hovered.fg_stroke = Stroke::new(1.5_f32, GREEN);
    w.hovered.rounding = r;

    w.active.bg_fill = Color32::from_rgb(30, 70, 46);
    w.active.weak_bg_fill = Color32::from_rgb(30, 70, 46);
    w.active.bg_stroke = Stroke::new(1.0_f32, GREEN);
    w.active.fg_stroke = Stroke::new(2.0_f32, GREEN);
    w.active.rounding = r;

    w.open = w.active;

    ctx.set_visuals(v);

    ctx.style_mut(|s| {
        // Everything in monospace for the terminal feel.
        s.text_styles = [
            (TextStyle::Heading, FontId::new(18.0, FontFamily::Monospace)),
            (TextStyle::Body, FontId::new(13.5, FontFamily::Monospace)),
            (TextStyle::Monospace, FontId::new(13.5, FontFamily::Monospace)),
            (TextStyle::Button, FontId::new(13.0, FontFamily::Monospace)),
            (TextStyle::Small, FontId::new(11.0, FontFamily::Monospace)),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
        s.spacing.interact_size.y = 24.0;
    });
}
