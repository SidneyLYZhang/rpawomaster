//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-30
// Version : 0.1.8
// License : Mulan PSL v2
//
// A secure password manager written in Rust.

mod commands;
mod pwsmanager;
mod passgen;
mod securecrypto;
mod configtool;
mod xotp;

use clap::{Parser, Args};
use serde::{Serialize, Deserialize};
use crate::passgen::Capitalization;

#[derive(Debug, Parser)]
#[command(name = "rpawomaster")]
#[command(author, version, about = "A secure password manager written in Rust", long_about = None)]

enum Cli {
    /// Initialize a new password vault
    Init {
        /// Core Username
        #[arg(short, long)]
        user: Option<String>,

        /// Path to configuration file to import
        #[arg(short, long)]
        import: Option<String>,
    },

    /// Generate a new password
    Gen {
        #[command(subcommand)]
        subcommand: GenSubcommand,
    },

    /// Add a password to the vault
    Add {
        /// User to add password for
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to add password to
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Update an existing password
    Update {
        #[arg(short, long)]
        all: Option<bool>,

        /// Password name to update
        #[arg(short, long)]
        passwordname: Option<String>,

        /// User to update password for
        #[arg(short, long)]
        user: Option<String>,

        /// Vault to update password in 
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Delete an existing password
    Delete {
        /// Password name to delete
        passwordname: String,

        /// User to delete password from
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to delete password from
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// list all existing passwords
    List {
        /// User to filter passwords by
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to list passwords from
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Search passwords in the vault
    Search {
        /// Text to search for
        text: String,
        
        /// User to filter passwords by
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to search in
        #[arg(short, long)]
        vault: Option<String>,

        /// Search for exact match
        #[arg(short, long)]
        exact: Option<bool>,
    },

    /// Test password strength and properties
    Testpass(TestpassArgs),

    /// List all password vaults
    Vaults {
        /// User to list vaults for
        #[arg(short, long)]
        user: Option<String>,
    },

    /// Encrypt or decrypt files/directories
    Crypt {
        #[command(subcommand)]
        subcommand: CryptSubcommand,
    },

    /// Export password vault
    Export {
        /// Export user data
        user: String,
        
        /// Path to export file
        #[arg(short, long)]
        path: Option<String>,

        /// Vault to export
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Manage OTP
    Xotp {
        #[command(subcommand)]
        subcommand: XotpSubcommand,
    }
}

#[derive(Debug, Parser)]
enum XotpSubcommand {
    /// Add a new OTP
    Add {
        /// password name
        #[arg(short, long)]
        name: String,

        /// User to add OTP to
        #[arg(short, long)]
        user: Option<String>,

        /// Vault to add OTP to
        #[arg(short, long)]
        vault: Option<String>,

        /// OTP secret or OTP url
        #[arg(short, long)]
        secret: String,
    },

    /// List all OTPs
    List {
        /// User to list OTPs for
        #[arg(short, long)]
        user: Option<String>,

        /// Vault to list OTPs from
        #[arg(short, long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Parser)]
enum GenSubcommand {
    /// Generate a random password
    Random(GenRandomArgs),
    
    /// Generate a memorable password
    Memorable(GenMemorableArgs),
}

#[derive(Debug, Parser)]
enum CryptSubcommand {
    /// Encrypt a file or directory
    En {
        /// Password to use for encryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Source path to encrypt
        #[arg(short, long)]
        source: String,
        
        /// Target path to save encrypted file
        #[arg(short, long)]
        target: String,
    },
    
    /// Decrypt a file or directory
    De {
        /// Password to use for decryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Source path to decrypt
        #[arg(short, long)]
        source: String,
        
        /// Target path to save decrypted file
        #[arg(short, long)]
        target: String,
    },
}

#[derive(Debug, Parser)]
struct GenRandomArgs {
    /// Length of the password
    #[arg(short, long, default_value_t = 12)]
    length: usize,

    /// Exclude uppercase letters
    #[arg(long, default_value_t = false)]
    no_uppercase: bool,

    /// Exclude lowercase letters
    #[arg(long, default_value_t = false)]
    no_lowercase: bool,

    /// Exclude numbers
    #[arg(long, default_value_t = false)]
    no_numbers: bool,

    /// Exclude special characters
    #[arg(long, default_value_t = false)]
    no_special: bool,

    /// Make password URL-safe
    #[arg(short = 's', long, default_value_t = false)]
    url_safe: bool,

    /// Avoid visually confusing characters
    #[arg(short = 'c', long, default_value_t = false)]
    avoid_confusion: bool,
}

#[derive(Debug, Parser)]
struct GenMemorableArgs {
    /// Number of words in the password
    #[arg(short, long, default_value_t = 4)]
    words: usize,

    /// Separator character between words
    #[arg(short, long, default_value_t = '-')]
    separator: char,

    /// Include numbers in the password
    #[arg(short, long, default_value_t = false)]
    include_numbers: bool,

    /// Capitalization style (none, camel, random)
    #[arg(short, long, default_value_t = Capitalization::CamelCase)]
    capitalization: Capitalization,
}

#[derive(Debug, Args, Serialize, Deserialize)]
struct TestpassArgs {
    /// Password to test
    password: String,

    /// Check if password is URL-safe
    #[arg(short = 's', long, default_value_t = false)]
    check_url_safe: bool,

    /// Check for visually confusing characters
    #[arg(short = 'c', long, default_value_t = false)]
    check_confusion: bool,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli {
        Cli::Init { user, import } => {
            if let Some(import_path) = import {
                let vault_path = configtool::prompt_input("Enter vault path (default: config path): ")?;
                let vault_path = if vault_path.is_empty() {
                    configtool::get_config_dir()?.to_string_lossy().to_string()
                } else {
                    vault_path
                };
                commands::import::import_passvaults(import_path, vault_path).map_err(|e| e.to_string())
            } else {
                commands::init::interactive_init(user)
            }
        },
        Cli::Gen { subcommand } => match subcommand {
            GenSubcommand::Random(args) => {
                commands::password_gen::generate_random(
                    args.length,
                    args.no_uppercase,
                    args.no_lowercase,
                    args.no_numbers,
                    args.no_special,
                    args.url_safe,
                    args.avoid_confusion,
                )
            },
            GenSubcommand::Memorable(args) => {
                commands::password_gen::generate_memorable(
                    args.words,
                    args.separator,
                    args.include_numbers,
                    args.capitalization,
                )
            }
        },
        Cli::Add { user, vault } => {
            commands::add::add_password_interactive(user, vault)
        },
        Cli::Update { all, passwordname, user, vault } => {
            commands::update::update_password(all, passwordname, user, vault)
        },
        Cli::Delete { passwordname, user, vault } => {
            commands::delete::delete_password(passwordname, user, vault)
        },
        Cli::List { user, vault } => {
            commands::list::list_passwords(user, vault)
        },
        Cli::Search { text, user, vault, exact } => {
            commands::search::search_passwords(text, user, vault, exact)
        },
        Cli::Testpass(args) => {
            commands::testpass::test_password(args.password, args.check_url_safe, args.check_confusion)
        },
        Cli::Vaults { user } => {
            commands::vaults::list_vaults(user)
        },
        Cli::Crypt { subcommand } => match subcommand {
            CryptSubcommand::En { password, source, target } => {
                commands::crypt::encrypt_path(password, source, target)
            },
            CryptSubcommand::De { password, source, target } => {
                commands::crypt::decrypt_path(password, source, target)
            }
        },
        Cli::Export { user, path , vault } => {
            commands::export::export_vault(user, path, vault)
        },
        Cli::Xotp { subcommand } => {
            match subcommand {
                XotpSubcommand::Add { name, user, vault, secret } => {
                    commands::xotp::add_otp(name, user, vault, secret)
                },
                XotpSubcommand::List { user, vault } => {
                    commands::xotp::list_otps(user, vault)
                },
            }
        },
    }
}
