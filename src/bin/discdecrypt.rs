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

use isob3_tools::dbenc::{decrypt_file_to_path, is_encrypted_file};

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
    #[arg(long)]
    password: Option<String>,
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
    let password = cli.password.unwrap_or_else(|| match prompt("Password") {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => {
            eprintln!("password is required");
            std::process::exit(2);
        }
        Err(err) => {
            eprintln!("failed to read password: {err}");
            std::process::exit(2);
        }
    });

    match run(&cli.input, &output, &password) {
        Ok(summary) => println!("{summary}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    }
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

#[derive(Default)]
struct DiscDecryptApp {
    input: String,
    output: String,
    password: String,
    status: String,
    running: bool,
    rx: Option<Receiver<Result<String, String>>>,
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
            ui.label("Password:");
            ui.add_enabled(
                !self.running,
                egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );

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
        let password = self.password.clone();

        if input.is_empty() {
            self.status = "ERROR: input folder is required".to_string();
            return;
        }
        if output.is_empty() {
            self.status = "ERROR: output folder is required".to_string();
            return;
        }
        if password.is_empty() {
            self.status = "ERROR: password is required".to_string();
            return;
        }

        let input = PathBuf::from(input);
        let output = PathBuf::from(output);
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.running = true;
        self.status = "Decrypting...".to_string();

        thread::spawn(move || {
            let result = run(&input, &output, &password);
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

fn run(input_root: &Path, output_root: &Path, password: &str) -> Result<String, String> {
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
            decrypt_file_to_path(path, &destination, password)
                .map_err(|e| format!("decrypt failed for {}: {e}", path.display()))?;
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
