use anyhow::{anyhow, Context, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use rpassword::prompt_password;
use sha2::Sha256;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// Change these to customize defaults at compile time.
const DEFAULT_KEY_FILE: &str = "p.bin";
const DERIVE_SALT: &str = "MY_SALT_HERE"; // PBKDF2 salt

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // We support:
    //   --keygen               => derive a key from password (PBKDF2)
    //   --E <in> <out>         => encrypt from in to out
    //   --D <in> <out>         => decrypt from in to out
    //   --E --over <file>      => encrypt in place
    //   --D --over <file>      => decrypt in place

    // Show usage if no arguments
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    // 1) Check for --keygen first
    if args.contains(&"--keygen".to_string()) {
        keygen_mode()?;
        return Ok(());
    }

    // 2) If not keygen, parse --E / --D plus optional --over
    let encrypt_index = args.iter().position(|x| x == "--E");
    let decrypt_index = args.iter().position(|x| x == "--D");
    let over_index = args.iter().position(|x| x == "--over");

    match (encrypt_index, decrypt_index, over_index) {
        // --E --over <file>
        (Some(ei), None, Some(oi)) if ei < oi => {
            if args.len() < oi + 2 {
                eprintln!("Missing file argument for --over mode.");
                std::process::exit(1);
            }
            let file_path = &args[oi + 1];
            encrypt_in_place(file_path, DEFAULT_KEY_FILE)?;
        }
        // --D --over <file>
        (None, Some(di), Some(oi)) if di < oi => {
            if args.len() < oi + 2 {
                eprintln!("Missing file argument for --over mode.");
                std::process::exit(1);
            }
            let file_path = &args[oi + 1];
            decrypt_in_place(file_path, DEFAULT_KEY_FILE)?;
        }
        // --E <in> <out>
        (Some(ei), None, None) => {
            if args.len() < ei + 3 {
                eprintln!("Expected: --E <input_file> <output_file>");
                std::process::exit(1);
            }
            let input_path = &args[ei + 1];
            let output_path = &args[ei + 2];
            encrypt_file(input_path, output_path, DEFAULT_KEY_FILE)?;
        }
        // --D <in> <out>
        (None, Some(di), None) => {
            if args.len() < di + 3 {
                eprintln!("Expected: --D <input_file> <output_file>");
                std::process::exit(1);
            }
            let input_path = &args[di + 1];
            let output_path = &args[di + 2];
            decrypt_file(input_path, output_path, DEFAULT_KEY_FILE)?;
        }
        // Anything else => usage
        _ => {
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage(prog_name: &str) {
    eprintln!(
        "Usage:
  {0} --keygen
  {0} --E <input_file> <output_file>
  {0} --D <input_file> <output_file>
  {0} --E --over <file>
  {0} --D --over <file>

* --keygen will derive a 32-byte key from a password (using PBKDF2) \
  and write it to '{1}' (by default).
* --E means encrypt, --D means decrypt.
* --over performs in-place encryption/decryption with atomic overwrite.",
        prog_name, DEFAULT_KEY_FILE
    );
}

// =====================
//  Key Generation Mode
// =====================

fn keygen_mode() -> Result<()> {
    // Prompt for password (hidden)
    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err(anyhow!("Passwords do not match. Aborting."));
    }

    // Derive a 32-byte key with PBKDF2-HMAC-SHA256
    let mut key_buf = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        DERIVE_SALT.as_bytes(),
        100_000, // tweak iterations for your security/performance needs
        &mut key_buf,
    );

    // Write to file
    fs::write(DEFAULT_KEY_FILE, &key_buf)
        .with_context(|| format!("Failed to write key file '{}'", DEFAULT_KEY_FILE))?;

    // Zeroize
    let mut pw_vec = password.into_bytes();
    pw_vec.zeroize();
    key_buf.zeroize();

    println!("Key derived and written to '{}'.", DEFAULT_KEY_FILE);
    Ok(())
}

// ===================================
//  In-Place Encrypt / Decrypt (--over)
// ===================================

fn encrypt_in_place(path_str: &str, key_file_path: &str) -> Result<()> {
    let path = Path::new(path_str);

    // 1. Read file
    let plaintext = fs::read(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    // 2. Load key
    let key = load_key(key_file_path)?;
    if key.len() != 32 {
        return Err(anyhow!(
            "Key length must be 32 bytes for AES-256 (got {})",
            key.len()
        ));
    }

    // 3. Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create AES-256-GCM: {e:?}"))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // plaintext is a Vec<u8>, so we use plaintext.as_slice()
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e:?}"))?;

    // 4. Combine [nonce | ciphertext]
    let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // 5. Atomic write
    atomic_write(path, &combined)?;

    // 6. Zeroize
    zeroize_memory(key, plaintext);
    combined.zeroize();

    println!("Encrypted in place: {}", path.display());
    Ok(())
}

fn decrypt_in_place(path_str: &str, key_file_path: &str) -> Result<()> {
    let path = Path::new(path_str);

    // 1. Read file
    let encrypted_file = fs::read(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    if encrypted_file.len() < 12 {
        return Err(anyhow!(
            "File '{}' is too short to contain the AES-GCM nonce",
            path.display()
        ));
    }

    // 2. Load key
    let key = load_key(key_file_path)?;
    if key.len() != 32 {
        return Err(anyhow!(
            "Key length must be 32 bytes for AES-256 (got {})",
            key.len()
        ));
    }

    // 3. Separate nonce & ciphertext
    let (nonce_bytes, ciphertext) = encrypted_file.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create AES-256-GCM: {e:?}"))?;

    // ciphertext is already a &[u8], so we can pass it directly
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {e:?}"))?;

    // 5. Atomic write
    atomic_write(path, &plaintext)?;

    // 6. Zeroize
    zeroize_memory(key, plaintext);

    println!("Decrypted in place: {}", path.display());
    Ok(())
}

// ==================================
//  Standard Encrypt / Decrypt (--E/--D)
// ==================================

fn encrypt_file(input_path: &str, output_path: &str, key_file_path: &str) -> Result<()> {
    // 1. Load key
    let key = load_key(key_file_path)?;
    if key.len() != 32 {
        return Err(anyhow!(
            "Key length must be 32 bytes for AES-256 (got {})",
            key.len()
        ));
    }

    // 2. Read plaintext
    let plaintext = fs::read(input_path)
        .with_context(|| format!("Failed to read input file '{}'", input_path))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create AES-256-GCM: {e:?}"))?;

    // 3. Generate nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // plaintext is a Vec<u8>, so use .as_slice()
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e:?}"))?;

    // 4. Write [nonce | ciphertext]
    let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    fs::write(output_path, &combined)
        .with_context(|| format!("Failed to write output file '{}'", output_path))?;

    zeroize_memory(key, plaintext);
    combined.zeroize();

    println!("Encrypted: {} -> {}", input_path, output_path);
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, key_file_path: &str) -> Result<()> {
    // 1. Load key
    let key = load_key(key_file_path)?;
    if key.len() != 32 {
        return Err(anyhow!(
            "Key length must be 32 bytes for AES-256 (got {})",
            key.len()
        ));
    }

    // 2. Read file
    let encrypted_file = fs::read(input_path)
        .with_context(|| format!("Failed to read input file '{}'", input_path))?;

    if encrypted_file.len() < 12 {
        return Err(anyhow!(
            "File '{}' is too short to contain a nonce",
            input_path
        ));
    }

    // 3. Separate nonce & ciphertext
    let (nonce_bytes, ciphertext) = encrypted_file.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create AES-256-GCM: {e:?}"))?;

    // ciphertext is &[u8], so just pass it directly
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {e:?}"))?;

    fs::write(output_path, &plaintext)
        .with_context(|| format!("Failed to write decrypted data to '{}'", output_path))?;

    zeroize_memory(key, plaintext);

    println!("Decrypted: {} -> {}", input_path, output_path);
    Ok(())
}

// ============
//  Utilities
// ============

/// Loads the key from file.
fn load_key(path: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read key file '{}'", path))
}

/// Overwrite data atomically by writing to a temporary file in the same directory, then rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp_path = PathBuf::from(path);
    let file_name = match tmp_path.file_name() {
        Some(name) => name.to_owned(),
        None => {
            return Err(anyhow!(
                "Cannot determine file name for atomic write: '{}'",
                path.display()
            ));
        }
    };

    // e.g. "myfile.txt.tmp"
    tmp_path.set_file_name(format!("{}.tmp", file_name.to_string_lossy()));

    // 1. Write data to temp file
    fs::write(&tmp_path, data)
        .with_context(|| format!("Failed to write temporary file '{}'", tmp_path.display()))?;

    // 2. Rename temp file -> original
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename '{}' -> '{}'",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

/// Zeroizes key + data in memory.
fn zeroize_memory(mut key: Vec<u8>, mut data: Vec<u8>) {
    key.zeroize();
    data.zeroize();
}

