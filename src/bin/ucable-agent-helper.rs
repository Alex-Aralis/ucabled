//! Native GTK4 UI helper for ucabled.
//!
//! The session agent spawns this program once per prompt (see
//! `docs/helper-contract.md`). It renders the caBLE QR code in the passkey
//! style, or asks whether to use the phone instead of an already-connected
//! security key.
//!
//! Build with `--features adwaita` for GNOME-native window chrome.

use std::collections::VecDeque;
use std::f64::consts::PI;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gtk::prelude::*;
use gtk::{cairo, gdk, glib};

/// Exit status meaning "use the phone" in select mode.
const EXIT_USE_PHONE: i32 = 0;
/// Exit status meaning "decline" / "keep the security key".
const EXIT_DECLINE: i32 = 1;

/// CSS class toggled on the QR picture when the daemon reports `found`.
const FOUND_CSS_CLASS: &str = "blurred";

/// The blur rule behind [`FOUND_CSS_CLASS`]: once the phone is detected the
/// code must stay visible but unscannable.
fn blur_css() -> String {
    format!(".{FOUND_CSS_CLASS} {{ filter: blur(12px); opacity: 0.55; }}")
}

/// Pixels per QR module in the rendered bitmap.
const QR_MODULE_PX: i32 = 10;
/// Quiet zone around the code, in modules.
const QR_QUIET: i32 = 4;
/// Side of the centre image, in modules.
const QR_CENTER_MODULES: i32 = 10;
/// Smallest QR version used when a centre image is drawn (37 modules), so the
/// icon cannot eat enough of the error-correction budget to break decoding.
const QR_MIN_VERSION: i16 = 5;

/// The passkey glyph: an 8-bit grayscale mask (0 = ink, 255 = paper), 100x100,
/// stamped into a `QR_CENTER_MODULES` patch. Regenerate with `rsvg-convert
/// -w 100 -h 100 -b white passkey.svg` piped through `ffmpeg -pix_fmt gray`.
const PASSKEY_ICON: &[u8; 100 * 100] = include_bytes!("resources/passkey.gray");

/// gettext domain for this helper's catalogs.
const GETTEXT_DOMAIN: &str = "ucable";

/// Where gettext catalogs are installed.  `UCABLED_LOCALEDIR` wins when set
/// at build time; otherwise the directory is derived from the executable's
/// own location so any install prefix works without a wrapper.
fn localedir() -> String {
    if let Some(dir) = option_env!("UCABLED_LOCALEDIR") {
        return dir.to_string();
    }
    std::env::current_exe()
        .ok()
        .map(|exe| localedir_for_exe(&exe))
        .unwrap_or_else(|| "/usr/local/share/locale".to_string())
}

/// `<prefix>/bin/<helper>` maps to `<prefix>/share/locale`; anything else
/// falls back to the default install prefix.
fn localedir_for_exe(exe: &Path) -> String {
    exe.parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("share/locale"))
        .unwrap_or_else(|| PathBuf::from("/usr/local/share/locale"))
        .to_string_lossy()
        .into_owned()
}

/// Which CTAP command the daemon is relaying, as handed over on argv.  It only
/// decides how the QR page phrases the scan, so a value we do not know — or
/// none at all — falls back to the plain caption.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    MakeCredential,
    GetAssertion,
}

impl RequestKind {
    /// The contract spells the values `mc` / `ga`, mirroring the request type
    /// inside the caBLE URL (PXP §5.3.1, key 5).
    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "mc" => Some(RequestKind::MakeCredential),
            "ga" => Some(RequestKind::GetAssertion),
            _ => None,
        }
    }
}

/// The caption under the QR code: what scanning does, in the terms of the
/// command that is waiting on the other end.
/// Marks a literal for translation extraction without translating it here:
/// the caller passes the value to [`tr`].  `xgettext` is told about it with
/// `--keyword=n_` (see `admin/update-pot.sh`), which a plain `tr()` around
/// these literals could not be, because the function returns a `&'static str`.
const fn n_(msgid: &'static str) -> &'static str {
    msgid
}

fn scan_caption(request_type: Option<RequestKind>) -> &'static str {
    match request_type {
        Some(RequestKind::MakeCredential) => n_("Scan with your phone\nto store a passkey"),
        Some(RequestKind::GetAssertion) => {
            n_("Scan with your phone\nto authenticate with passkeys")
        }
        None => n_("Scan with your phone"),
    }
}

#[derive(Clone)]
struct Options {
    select: bool,
    timeout: Duration,
    rp: Option<String>,
    url: Option<String>,
    request_type: Option<RequestKind>,
}

fn parse_args() -> Options {
    let mut opts = Options {
        select: false,
        timeout: Duration::from_secs(300),
        rp: None,
        url: None,
        request_type: None,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--select" => opts.select = true,
            "--timeout" => {
                if let Some(secs) = args.next().and_then(|v| v.parse::<u64>().ok()) {
                    opts.timeout = Duration::from_secs(secs);
                }
            }
            "--request-type" => {
                if let Some(value) = args.next() {
                    opts.request_type = RequestKind::from_wire(&value);
                }
            }
            _ => {
                if let Some(secs) = arg
                    .strip_prefix("--timeout=")
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    opts.timeout = Duration::from_secs(secs);
                } else if let Some(value) = arg.strip_prefix("--request-type=") {
                    opts.request_type = RequestKind::from_wire(value);
                } else if arg.starts_with("FIDO:/") && opts.url.is_none() {
                    // Historical tolerance; the contract sends the URL on stdin.
                    opts.url = Some(arg);
                } else if !arg.starts_with('-') && opts.rp.is_none() {
                    opts.rp = Some(arg);
                }
            }
        }
    }

    opts
}

// --------------------------------------------------------------------------
// i18n
// --------------------------------------------------------------------------

fn init_i18n() {
    use gettextrs::{LocaleCategory, bindtextdomain, setlocale, textdomain};

    // GTK4 dropped the setlocale() that GTK3 did at init, so without this the
    // process stays in the "C" locale and gettext never loads a catalog.
    // SAFETY: single-threaded here; this runs before the GTK main loop.
    unsafe {
        setlocale(LocaleCategory::LcAll, "");
    }
    let _ = bindtextdomain(GETTEXT_DOMAIN, localedir());
    let _ = textdomain(GETTEXT_DOMAIN);
}

/// Translate `msgid`; without a catalog the msgid is the English string, which
/// is returned unchanged.
fn tr(msgid: &str) -> String {
    gettextrs::gettext(msgid)
}

// --------------------------------------------------------------------------
// QR rendering
// --------------------------------------------------------------------------

/// Build the QR code with error-correction level M and at least version
/// [`QR_MIN_VERSION`] (so the centre icon cannot eat enough of the
/// error-correction budget to break decoding).
fn make_qr_code(url: &str) -> qrcode::QrCode {
    // Let the encoder pick the natural version first; bumping a tiny payload
    // up to the minimum is one re-encode, versus trying every version from
    // the minimum up to the one that fits.
    let code = qrcode::QrCode::with_error_correction_level(url.as_bytes(), qrcode::EcLevel::M)
        .expect("QR contents too long");
    match code.version() {
        qrcode::Version::Normal(v) if v < QR_MIN_VERSION => qrcode::QrCode::with_version(
            url.as_bytes(),
            qrcode::Version::Normal(QR_MIN_VERSION),
            qrcode::EcLevel::M,
        )
        .expect("a payload that fit a smaller version fits QR_MIN_VERSION"),
        _ => code,
    }
}

/// Rounded-rectangle path (four corner arcs).
fn rounded_rect(cr: &cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
    let r = r.min(w / 2.0).min(h / 2.0);
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -PI / 2.0, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, PI / 2.0);
    cr.arc(x + r, y + h - r, r, PI / 2.0, PI);
    cr.arc(x + r, y + r, r, PI, 3.0 * PI / 2.0);
    cr.close_path();
}

/// Is (x, y) part of one of the three 7x7 finder patterns?
fn is_locator(x: i32, y: i32, n: i32) -> bool {
    let top = y < 7;
    let bottom = y >= n - 7;
    let left = x < 7;
    let right = x >= n - 7;
    (top && (left || right)) || (bottom && left)
}

/// One finder pattern as three nested rounded rectangles — a 7x7 ring, a 5x5
/// white gap and a 3x3 core, each with a corner radius of one module.
fn draw_locator(cr: &cairo::Context, ox: f64, oy: f64, module: f64) {
    let r = module;

    cr.set_source_rgb(0.0, 0.0, 0.0);
    rounded_rect(cr, ox, oy, 7.0 * module, 7.0 * module, r);
    cr.fill().ok();

    cr.set_source_rgb(1.0, 1.0, 1.0);
    rounded_rect(cr, ox + module, oy + module, 5.0 * module, 5.0 * module, r);
    cr.fill().ok();

    cr.set_source_rgb(0.0, 0.0, 0.0);
    rounded_rect(
        cr,
        ox + 2.0 * module,
        oy + 2.0 * module,
        3.0 * module,
        3.0 * module,
        r,
    );
    cr.fill().ok();
}

/// Stamp the passkey icon onto a cleared, module-aligned patch in the centre.
fn draw_center_icon(cr: &cairo::Context, n: i32, module: f64) {
    const IW: usize = 100;

    let box_px = QR_CENTER_MODULES as f64 * module;
    let origin = ((n - QR_CENTER_MODULES) / 2 + QR_QUIET) as f64;
    let (x0, y0) = (origin * module, origin * module);

    // Clear a white patch; it already falls on the module grid.
    cr.set_source_rgb(1.0, 1.0, 1.0);
    cr.rectangle(x0, y0, box_px, box_px);
    cr.fill().ok();

    // Expand the grayscale mask into an opaque black-on-white ARGB surface.
    let mut buf = vec![0u8; IW * IW * 4];
    for (i, &g) in PASSKEY_ICON.iter().enumerate() {
        buf[i * 4] = g;
        buf[i * 4 + 1] = g;
        buf[i * 4 + 2] = g;
        buf[i * 4 + 3] = 255;
    }
    let Ok(icon) = cairo::ImageSurface::create_for_data(
        buf,
        cairo::Format::ARgb32,
        IW as i32,
        IW as i32,
        (IW * 4) as i32,
    ) else {
        return;
    };

    cr.save().ok();
    cr.rectangle(x0, y0, box_px, box_px);
    cr.clip();
    cr.translate(x0, y0);
    cr.scale(box_px / IW as f64, box_px / IW as f64);
    cr.set_source_surface(&icon, 0.0, 0.0).ok();
    cr.paint().ok();
    cr.restore().ok();
}

/// Rasterize a caBLE URL into a GDK texture: round data modules and rounded
/// finder patterns, with the passkey glyph in the middle. The URL is secret and
/// must never be printed.
fn qr_texture(url: &str) -> Option<gdk::Texture> {
    let code = make_qr_code(url);
    let n = code.width() as i32;
    let dim = (n + 2 * QR_QUIET) * QR_MODULE_PX;

    let mut surface = cairo::ImageSurface::create(cairo::Format::ARgb32, dim, dim).ok()?;
    {
        let cr = cairo::Context::new(&surface).ok()?;
        cr.set_source_rgb(1.0, 1.0, 1.0);
        cr.paint().ok()?;

        let module = QR_MODULE_PX as f64;
        // One path for every data module: an arc per dark module (each its
        // own subpath, or cairo would connect them with line segments) and a
        // single fill, instead of a set_source/fill per module.
        cr.set_source_rgb(0.0, 0.0, 0.0);
        for y in 0..n {
            for x in 0..n {
                if is_locator(x, y, n) {
                    continue;
                }
                if code[(x as usize, y as usize)] != qrcode::types::Color::Dark {
                    continue;
                }
                let cx = (x as f64 + QR_QUIET as f64 + 0.5) * module;
                let cy = (y as f64 + QR_QUIET as f64 + 0.5) * module;
                let r = module / 2.0 - 1.0;
                cr.new_sub_path();
                cr.arc(cx, cy, r, 0.0, 2.0 * PI);
            }
        }
        cr.fill().ok()?;

        let q = QR_QUIET as f64 * module;
        let far = (QR_QUIET + n - 7) as f64 * module;
        draw_locator(&cr, q, q, module);
        draw_locator(&cr, far, q, module);
        draw_locator(&cr, q, far, module);

        draw_center_icon(&cr, n, module);
    }

    surface.flush();
    let stride = surface.stride() as usize;
    let data = surface.data().ok()?.to_vec();
    let bytes = glib::Bytes::from_owned(data);
    // Cairo ARGB32 is BGRA in memory (little-endian); the image is opaque, so
    // premultiplication does not matter.
    let texture = gdk::MemoryTexture::new(dim, dim, gdk::MemoryFormat::B8g8r8a8, &bytes, stride);
    Some(texture.upcast())
}

// --------------------------------------------------------------------------
// Window chrome
// --------------------------------------------------------------------------

#[cfg(feature = "adwaita")]
fn new_app_window(app: &gtk::Application) -> gtk::ApplicationWindow {
    adw::ApplicationWindow::builder()
        .application(app)
        .build()
        .upcast()
}

#[cfg(not(feature = "adwaita"))]
fn new_app_window(app: &gtk::Application) -> gtk::ApplicationWindow {
    gtk::ApplicationWindow::builder().application(app).build()
}

/// A normal window gets a header bar, which carries the close button — the only
/// mouse-driven way out (Esc works too, but assumes a keyboard).
#[cfg(feature = "adwaita")]
fn header_bar() -> gtk::Widget {
    adw::HeaderBar::new().upcast()
}

#[cfg(not(feature = "adwaita"))]
fn header_bar() -> gtk::Widget {
    gtk::HeaderBar::new().upcast()
}

/// Install the blur rule for [`FOUND_CSS_CLASS`]; needed on every window kind.
fn install_blur_css(window: &gtk::ApplicationWindow) {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(&blur_css());
    gtk::style_context_add_provider_for_display(
        &gtk::prelude::WidgetExt::display(window),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

/// Attach the page to the window, under a header bar with a close button.
fn set_window_content(window: &gtk::ApplicationWindow, content: &impl IsA<gtk::Widget>) {
    window.set_titlebar(Some(&header_bar()));
    window.set_child(Some(content));
}

// --------------------------------------------------------------------------
// UI
// --------------------------------------------------------------------------

fn status_page(title: &str, subtitle: &str) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_halign(gtk::Align::Center);
    page.set_valign(gtk::Align::Center);

    let title_label = gtk::Label::new(Some(title));
    title_label.add_css_class("title-2");
    page.append(&title_label);

    let subtitle_label = gtk::Label::new(Some(subtitle));
    subtitle_label.add_css_class("dim-label");
    subtitle_label.set_wrap(true);
    subtitle_label.set_justify(gtk::Justification::Center);
    page.append(&subtitle_label);

    page
}

fn build_qr_window(window: &gtk::ApplicationWindow, opts: &Options) {
    window.set_default_size(380, 560);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.set_margin_top(24);
    content.set_margin_bottom(24);
    content.set_margin_start(24);
    content.set_margin_end(24);

    if let Some(rp) = &opts.rp {
        let rp_label = gtk::Label::new(Some(rp));
        rp_label.add_css_class("title-1");
        rp_label.set_wrap(true);
        rp_label.set_justify(gtk::Justification::Center);
        content.append(&rp_label);
    }

    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    stack.set_vexpand(true);

    let qr_page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    qr_page.set_halign(gtk::Align::Center);
    qr_page.set_valign(gtk::Align::Center);
    let picture = gtk::Picture::new();
    picture.set_can_shrink(true);
    picture.set_size_request(260, 260);
    qr_page.append(&picture);
    let caption = gtk::Label::new(Some(&tr(scan_caption(opts.request_type))));
    caption.add_css_class("title-3");
    caption.set_wrap(true);
    caption.set_justify(gtk::Justification::Center);
    qr_page.append(&caption);
    stack.add_named(&qr_page, Some("qr"));

    stack.add_named(
        &status_page(
            &tr("Code expired"),
            &tr("Close this window and start again."),
        ),
        Some("expired"),
    );
    stack.set_visible_child_name("qr");

    content.append(&stack);
    set_window_content(window, &content);

    watch_stdin(picture, caption, stack.clone(), opts.url.clone());

    if !opts.timeout.is_zero() {
        let stack = stack.clone();
        glib::timeout_add_seconds_local_once(opts.timeout.as_secs() as u32, move || {
            stack.set_visible_child_name("expired");
        });
    }
}

/// Caption for the phone-detected state: the strings are the same msgids the
/// gettext catalogs already carry, so existing translations keep applying.
fn found_caption() -> String {
    format!(
        "{}\n{}",
        tr("Phone detected"),
        tr("Confirm the sign-in on your phone")
    )
}

/// Fill the QR once the URL arrives on stdin, and blur the code when the
/// daemon reports `found`.
fn watch_stdin(
    picture: gtk::Picture,
    caption: gtk::Label,
    stack: gtk::Stack,
    initial_url: Option<String>,
) {
    let queue: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));

    {
        let queue = queue.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(line) => queue.lock().unwrap().push_back(line),
                    Err(_) => break,
                }
            }
        });
    }

    let mut got_url = false;
    if let Some(url) = initial_url {
        if let Some(texture) = qr_texture(&url) {
            picture.set_paintable(Some(&texture));
        }
        got_url = true;
    }

    glib::timeout_add_local(Duration::from_millis(50), move || {
        let mut pending = queue.lock().unwrap();
        while let Some(line) = pending.pop_front() {
            let line = line.trim();
            if !got_url {
                got_url = true;
                if !line.is_empty() {
                    if let Some(texture) = qr_texture(line) {
                        picture.set_paintable(Some(&texture));
                    }
                    stack.set_visible_child_name("qr");
                }
            } else if line == "found" {
                picture.add_css_class(FOUND_CSS_CLASS);
                caption.set_label(&found_caption());
            }
        }
        glib::ControlFlow::Continue
    });
}

fn build_select_window(window: &gtk::ApplicationWindow, opts: &Options) {
    window.set_default_size(400, 260);
    // Closing the window (Esc / the header-bar button) means "declined".
    window.connect_close_request(|_| {
        exit(EXIT_DECLINE);
    });

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.set_halign(gtk::Align::Center);
    content.set_valign(gtk::Align::Center);
    content.set_margin_top(24);
    content.set_margin_bottom(24);
    content.set_margin_start(24);
    content.set_margin_end(24);

    let title = gtk::Label::new(Some(&tr("Passkey request")));
    title.add_css_class("title-2");
    content.append(&title);

    let desc = gtk::Label::new(Some(&tr(
        "A security key is also connected. Use your phone's passkey instead?",
    )));
    desc.add_css_class("dim-label");
    desc.set_wrap(true);
    desc.set_justify(gtk::Justification::Center);
    content.append(&desc);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    buttons.set_halign(gtk::Align::Center);

    let keep = gtk::Button::with_label(&tr("Keep using the security key"));
    keep.connect_clicked(|_| exit(EXIT_DECLINE));
    buttons.append(&keep);

    let use_phone = gtk::Button::with_label(&tr("Use phone"));
    use_phone.add_css_class("suggested-action");
    use_phone.connect_clicked(|_| exit(EXIT_USE_PHONE));
    buttons.append(&use_phone);

    content.append(&buttons);
    set_window_content(window, &content);

    if !opts.timeout.is_zero() {
        glib::timeout_add_seconds_local_once(opts.timeout.as_secs() as u32, || {
            exit(EXIT_DECLINE);
        });
    }
}

/// Esc dismisses the window. It goes through the same path as the header-bar
/// close button, so the exit code is decided in one place: QR mode ends
/// normally (0), select mode reports "declined" (1).
fn bind_escape(window: &gtk::ApplicationWindow) {
    let keys = gtk::EventControllerKey::new();
    let win = window.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            win.close();
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    window.add_controller(keys);
}

fn activate(app: &gtk::Application, opts: Options) {
    let window = new_app_window(app);
    // The title is what the compositor and taskbar show. In QR mode it should
    // say what the window is asking for.
    let title = if opts.select {
        "ucabled".to_string()
    } else {
        tr("Passkey request")
    };
    window.set_title(Some(title.as_str()));
    window.set_resizable(false);

    bind_escape(&window);
    install_blur_css(&window);

    if opts.select {
        build_select_window(&window, &opts);
    } else {
        build_qr_window(&window, &opts);
    }

    window.present();
}

fn main() {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!(
                    "ucable-agent-helper {} — QR/selection window for ucable-agent\n\
                     \n\
                     Usage: ucable-agent-helper [RP] [--select] [--timeout SECS]\n\
                     \x20                           [--request-type mc|ga]\n\
                     \n\
                     The caBLE URL is read from the first stdin line; a later\n\
                     \"found\" line blurs the code and asks to confirm on the\n\
                     phone. In --select mode the exit status answers:\n\
                     \x20 0 = use the phone, 1 = decline.\n\
                     \n\
                     Options:\n\
                     \x20 -h, --help     print this help\n\
                     \x20 -V, --version  print the version",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("ucable-agent-helper {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let opts = parse_args();
    init_i18n();

    let app = gtk::Application::builder()
        .application_id("org.ucabled.Helper")
        .build();
    app.connect_activate(move |app| activate(app, opts.clone()));

    // Pass only the program name, so GTK does not try to parse our own options.
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "ucable-agent-helper".to_string());
    let code = app.run_with_args(&[argv0]);
    exit(code.get() as i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localedir_follows_the_install_prefix() {
        assert_eq!(
            localedir_for_exe(Path::new("/usr/local/bin/ucable-agent-helper")),
            "/usr/local/share/locale"
        );
        assert_eq!(
            localedir_for_exe(Path::new("/opt/ucabled/bin/ucable-agent-helper")),
            "/opt/ucabled/share/locale"
        );
        assert_eq!(
            localedir_for_exe(Path::new("/ucable-agent-helper")),
            "/usr/local/share/locale"
        );
    }

    #[test]
    fn caption_names_the_command_being_relayed() {
        assert_eq!(
            scan_caption(RequestKind::from_wire("ga")),
            "Scan with your phone\nto authenticate with passkeys"
        );
        assert_eq!(
            scan_caption(RequestKind::from_wire("mc")),
            "Scan with your phone\nto store a passkey"
        );
    }

    #[test]
    fn unknown_or_missing_request_type_keeps_the_plain_caption() {
        assert_eq!(scan_caption(None), "Scan with your phone");
        assert_eq!(
            scan_caption(RequestKind::from_wire("")),
            "Scan with your phone"
        );
        assert_eq!(
            scan_caption(RequestKind::from_wire("weird")),
            "Scan with your phone"
        );
    }

    #[test]
    fn found_state_blurs_the_code_with_the_translated_caption() {
        // The class toggled on `found` must have a matching blur rule.
        assert!(blur_css().contains(&format!(".{FOUND_CSS_CLASS}")));
        assert!(blur_css().contains("blur("));
        // The caption reuses msgids the gettext catalogs already carry.
        let caption = found_caption();
        assert!(caption.contains("Phone detected"));
        assert!(caption.contains("Confirm the sign-in on your phone"));
    }
}
