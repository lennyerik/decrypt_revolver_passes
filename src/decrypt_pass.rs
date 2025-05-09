mod decryption;

fn usage() -> ! {
    let executable = std::env::args()
        .next()
        .unwrap_or_else(|| "./decrypt_revolver_passes".to_owned());
    eprintln!("Usage: {executable} <BASE64PASSW>");
    std::process::exit(0)
}

fn main() -> Result<(), decryption::Error> {
    let passw = std::env::args().nth(1).unwrap_or_else(|| usage());
    println!("{}", decryption::decrypt_password(passw.trim())?);

    Ok(())
}
