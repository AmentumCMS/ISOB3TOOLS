use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use clap::Parser;
use eframe::egui;
use walkdir::WalkDir;

use isob3_tools::dbenc::{
    DbEncFormat, PQE_DK_LEN, decrypt_file_pqe_to_path, decrypt_file_to_path, detect_format,
    is_encrypted_file,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Parser)]
#[command(name = "discdecrypt")]
#[command(about = "Decrypt DBENC files from an extracted or mounted disc into an output folder.")]
struct Cli {
    #[arg(long, default_value = ".")]
    input: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
    /// Password for DBENC001–003 symmetric encryption.
    #[arg(long)]
    password: Option<String>,
    /// Path to ML-KEM-768 decapsulation key (.dk) for DBENC005 (PQE) files.
    #[arg(long)]
    private_key: Option<PathBuf>,
}

fn main() {
    if std::env::args_os().len() == 1 {
        if let Err(err) = run_gui() {
            eprintln!("{err}");
            std::process::exit(2);
        }
        return;
    }

    let cli = Cli::parse();
    let output = cli.output.unwrap_or_else(|| match prompt("Output directory") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        Ok(_) => {
            eprintln!("output directory is required");
            std::process::exit(2);
        }
        Err(err) => {
            eprintln!("failed to read output directory: {err}");
            std::process::exit(2);
        }
    });

    let private_key: Option<[u8; PQE_DK_LEN]> = match cli.private_key.as_deref() {
        Some(path) => match load_private_key(path) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        },
        None => {
            // Auto-discover default decapsulation key
            if let Some(default_dk) = default_key_dir().map(|d| d.join("default.dk")) {
                if default_dk.is_file() {
                    eprintln!("Using default decapsulation key: {}", default_dk.display());
                    match load_private_key(&default_dk) {
                        Ok(k) => Some(k),
                        Err(e) => {
                            eprintln!("{e}");
                            std::process::exit(2);
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
    };

    let password = if private_key.is_none() {
        Some(cli.password.unwrap_or_else(|| match prompt("Password") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                eprintln!("password is required");
                std::process::exit(2);
            }
            Err(err) => {
                eprintln!("failed to read password: {err}");
                std::process::exit(2);
            }
        }))
    } else {
        cli.password
    };

    match run(&cli.input, &output, password.as_deref(), private_key.as_ref()) {
        Ok(summary) => println!("{summary}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    }
}

fn default_key_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok()?;
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".isob3"))
}

fn load_private_key(path: &Path) -> Result<[u8; PQE_DK_LEN], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {} failed: {e}", path.display()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{} is not a valid ML-KEM-768 decapsulation key (expected {PQE_DK_LEN} bytes)", path.display()))
}

fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([620.0, 360.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Disc Decryptor",
        options,
        Box::new(|_cc| Ok(Box::new(DiscDecryptApp::default()))),
    )
}

struct DiscDecryptApp {
    input: String,
    output: String,
    password: String,
    private_key_input: String, // path to .dk file
    status: String,
    running: bool,
    rx: Option<Receiver<Result<String, String>>>,
}

impl Default for DiscDecryptApp {
    fn default() -> Self {
        // Pre-fill private key path if the default exists on disk.
        let private_key_input = default_key_dir()
            .map(|d| d.join("default.dk"))
            .filter(|p| p.is_file())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        Self {
            input: String::new(),
            output: String::new(),
            password: String::new(),
            private_key_input,
            status: String::new(),
            running: false,
            rx: None,
        }
    }
}

impl eframe::App for DiscDecryptApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        if let Some(rx) = &self.rx {
            if let Ok(result) = rx.try_recv() {
                self.running = false;
                self.rx = None;
                self.status = result.unwrap_or_else(|err| format!("ERROR: {err}"));
            }
        }

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Disc Decryptor");
            ui.label("Decrypt DBENC files from an extracted or mounted disc into an output folder.");
            ui.add_space(12.0);

            ui.label("Input folder or mounted disc root:");
            ui.horizontal(|ui| {
                let path_field_width = (ui.available_width() - 96.0).max(180.0);
                ui.add_enabled(
                    !self.running,
                    egui::TextEdit::singleline(&mut self.input)
                        .hint_text(r"G:\ or path\to\extracted-disc")
                        .desired_width(path_field_width),
                );
                if ui
                    .add_enabled(!self.running, egui::Button::new("Browse..."))
                    .clicked()
                {
                    match browse_folder("Select input folder or mounted disc root") {
                        Ok(Some(path)) => self.input = path.display().to_string(),
                        Ok(None) => {}
                        Err(err) => self.status = format!("ERROR: {err}"),
                    }
                }
            });

            ui.add_space(8.0);
            ui.label("Output folder:");
            ui.horizontal(|ui| {
                let path_field_width = (ui.available_width() - 96.0).max(180.0);
                ui.add_enabled(
                    !self.running,
                    egui::TextEdit::singleline(&mut self.output)
                        .hint_text(r"C:\Temp\decrypted-disc")
                        .desired_width(path_field_width),
                );
                if ui
                    .add_enabled(!self.running, egui::Button::new("Browse..."))
                    .clicked()
                {
                    match browse_folder("Select output folder") {
                        Ok(Some(path)) => self.output = path.display().to_string(),
                        Ok(None) => {}
                        Err(err) => self.status = format!("ERROR: {err}"),
                    }
                }
            });

            ui.add_space(8.0);

            // --- Decryption method ---
            ui.label("Decryption method (use one):");

            // Private key row (DBENC005 / PQE)
            ui.horizontal(|ui| {
                ui.label("  🔑 Private key (.dk):");
                let dk_hint = if self.private_key_input.is_empty() {
                    "path/to/key.dk (leave blank to use password below)"
                } else {
                    ""
                };
                ui.add_enabled(
                    !self.running,
                    egui::TextEdit::singleline(&mut self.private_key_input)
                        .hint_text(dk_hint)
                        .desired_width(300.0),
                );
                // Live existence indicator
                if !self.private_key_input.trim().is_empty() {
                    if std::path::Path::new(self.private_key_input.trim()).exists() {
                        ui.colored_label(egui::Color32::GREEN, "✔ found");
                    } else {
                        ui.colored_label(egui::Color32::RED, "✘ not found");
                    }
                } else {
                    ui.colored_label(egui::Color32::GRAY, "(none — will use password)");
                }
            });

            ui.add_space(4.0);

            // Password row (DBENC001–004)
            let using_key = !self.private_key_input.trim().is_empty();
            ui.horizontal(|ui| {
                ui.label("  🔒 Password:");
                ui.add_enabled(
                    !self.running && !using_key,
                    egui::TextEdit::singleline(&mut self.password)
                        .hint_text(if using_key {
                            "(not needed when private key is set)"
                        } else {
                            "password for DBENC001–DBENC004"
                        })
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            });
            if using_key {
                ui.colored_label(
                    egui::Color32::GRAY,
                    "  Private key takes priority — password field is ignored.",
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.running, egui::Button::new("Decrypt"))
                    .clicked()
                {
                    self.start_decrypt();
                }

                if self.running {
                    ui.label("Decrypting...");
                }
            });

            ui.add_space(12.0);
            ui.separator();
            ui.label("Status:");
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    ui.label(if self.status.is_empty() {
                        "Ready."
                    } else {
                        &self.status
                    });
                });
        });

        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

impl DiscDecryptApp {
    fn start_decrypt(&mut self) {
        let input = self.input.trim().to_string();
        let output = self.output.trim().to_string();
        let dk_path_str = self.private_key_input.trim().to_string();
        let password = self.password.clone();

        if input.is_empty() {
            self.status = "ERROR: input folder is required".to_string();
            return;
        }
        if output.is_empty() {
            self.status = "ERROR: output folder is required".to_string();
            return;
        }

        // Resolve private key — required if set, otherwise fall back to password
        let private_key: Option<[u8; PQE_DK_LEN]> = if !dk_path_str.is_empty() {
            match load_private_key(std::path::Path::new(&dk_path_str)) {
                Ok(k) => Some(k),
                Err(e) => {
                    self.status = format!("ERROR: {e}");
                    return;
                }
            }
        } else {
            None
        };

        // Password required only when no private key is loaded
        let password_opt: Option<String> = if private_key.is_none() {
            if password.is_empty() {
                self.status =
                    "ERROR: either a private key (.dk) or a password is required".to_string();
                return;
            }
            Some(password)
        } else {
            None
        };

        let input = PathBuf::from(input);
        let output = PathBuf::from(output);
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.running = true;
        self.status = "Decrypting...".to_string();

        thread::spawn(move || {
            let result = run(
                &input,
                &output,
                password_opt.as_deref(),
                private_key.as_ref(),
            );
            let _ = tx.send(result);
        });
    }
}

fn browse_folder(title: &str) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        let escaped_title = title.replace('\'', "''");
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $dialog = New-Object System.Windows.Forms.FolderBrowserDialog; \
             $dialog.Description = '{escaped_title}'; \
             $dialog.ShowNewFolderButton = $true; \
             if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ \
                 [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                 Write-Output $dialog.SelectedPath \
             }}"
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-STA", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("failed to open folder picker: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                "folder picker failed".to_string()
            } else {
                stderr
            });
        }

        let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if selected.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(selected)))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = title;
        Err("folder browsing is only implemented on Windows".to_string())
    }
}

fn run(
    input_root: &Path,
    output_root: &Path,
    password: Option<&str>,
    private_key: Option<&[u8; PQE_DK_LEN]>,
) -> Result<String, String> {
    if !input_root.is_dir() {
        return Err(format!(
            "input directory not found: {}",
            input_root.display()
        ));
    }

    let input_root = input_root
        .canonicalize()
        .map_err(|e| format!("failed to resolve input directory: {e}"))?;

    if output_root.exists() && !output_root.is_dir() {
        return Err(format!(
            "output path is not a directory: {}",
            output_root.display()
        ));
    }

    ensure_output_outside_input(&input_root, output_root)?;
    fs::create_dir_all(output_root).map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            output_root.display()
        )
    })?;

    let mut decrypted = 0usize;
    let mut copied = 0usize;

    for entry in WalkDir::new(&input_root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let relative = path.strip_prefix(&input_root).unwrap_or(path);
        if should_skip(relative) {
            continue;
        }
        let destination = output_root.join(relative);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination).map_err(|e| {
                format!(
                    "failed to create output directory {}: {e}",
                    destination.display()
                )
            })?;
            continue;
        }

        if is_encrypted_file(path)? {
            let fmt = detect_format(path)?;
            if fmt == Some(DbEncFormat::DbEnc005) {
                let dk = private_key.ok_or_else(|| {
                    format!(
                        "{} is DBENC005 (PQE) — pass --private-key <key.dk>",
                        path.display()
                    )
                })?;
                decrypt_file_pqe_to_path(path, &destination, dk)
                    .map_err(|e| format!("decrypt failed for {}: {e}", path.display()))?;
            } else {
                let pw = password.ok_or_else(|| {
                    format!(
                        "{} is password-encrypted — pass --password",
                        path.display()
                    )
                })?;
                decrypt_file_to_path(path, &destination, pw)
                    .map_err(|e| format!("decrypt failed for {}: {e}", path.display()))?;
            }
            decrypted += 1;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "failed to create output directory {}: {e}",
                        parent.display()
                    )
                })?;
            }
            fs::copy(path, &destination).map_err(|e| {
                format!(
                    "copy failed from {} to {}: {e}",
                    path.display(),
                    destination.display()
                )
            })?;
            copied += 1;
        }
    }

    Ok(format!(
        "Wrote decrypted disc contents to {}\nDecrypted {} file(s); copied {} plaintext file(s)",
        output_root.display(),
        decrypted,
        copied
    ))
}

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn ensure_output_outside_input(input_root: &Path, output_root: &Path) -> Result<(), String> {
    let candidate = if output_root.exists() {
        output_root
            .canonicalize()
            .map_err(|e| format!("failed to resolve output directory: {e}"))?
    } else if output_root.is_absolute() {
        output_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(output_root)
    };

    if candidate.starts_with(input_root) {
        return Err(format!(
            "output directory must be outside the input tree: {}",
            candidate.display()
        ));
    }

    Ok(())
}

fn should_skip(relative: &Path) -> bool {
    relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        == Some("decryptor")
}
