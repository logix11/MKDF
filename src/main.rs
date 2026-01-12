/*
* mkdf — password-based master key derivation and verification tool
* Copyright (C) 2026 L. M. Oukaci
*
* Contact: ouka.lotfi@gmail.com
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use clap::Parser;
use rand::{rngs::OsRng, TryRngCore}; // needed for salt
use rayon::join;
use std::io::{self, Read};
use yescrypt::{CustomizedPasswordHasher, Mode, Yescrypt};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Hash the password read from STDIN
    #[arg(long = "hash", conflicts_with = "verify")]
    hash: bool,

    /// Verify the password read from STDIN using the salts passed as arguments
    #[arg(short = 'v', long = "verify", conflicts_with = "hash")]
    verify: bool,

    /// Salt 1 (to hash the password and generate the MK works with verification only)
    #[arg(long, requires = "verify")]
    s1: Option<String>,

    /// Salt 2 (to hash the MK and generate the MK's digest work with verification only)
    #[arg(long, requires = "verify")]
    s2: Option<String>,

    /// Salt 3 (to hash the MK and generate the DPK works with verification only)
    #[arg(long, requires = "verify")]
    s3: Option<String>,

    /// Password's hash (actually the MK's hash)
    #[arg(long, requires = "verify")]
    phash: Option<String>,
}
fn main() {
    let args = Args::parse();
    if args.hash && args.verify {
        eprintln!("Exactly either -h or -v must be specified.");
        std::process::exit(64);
    } else if !args.hash && !args.verify {
        eprintln!("Exactly either -h or -v must be specified.");
        std::process::exit(64);
    }
    // Read password from STDIN
    let password = readpw()
        .map_err(|e| {
            eprintln!("failed to read password: {}", e);
            std::process::exit(2);
        })
        .unwrap();

    if args.hash {
        hash_password(&password);
        std::process::exit(0);
    } else {
        let (s1, s2, s3) = (args.s1.unwrap(), args.s2.unwrap(), args.s3.unwrap());
        if s1.len() != 32 || s2.len() != 32 || s3.len() != 32 {
            eprintln!("The salts must be 32 characters long (16 bytes long)");
            std::process::exit(64);
        }
        let (salt1, (salt2, salt3)) =
            join(|| get_salt(s1), || join(|| get_salt(s2), || get_salt(s3)));
        verify_password(
            &password,
            &salt1,
            &salt2,
            &salt3,
            args.phash.unwrap().as_str(),
        );
        std::process::exit(0);
    }
}

fn hash_password(password: &Vec<u8>) {
    let (salt1, (salt2, salt3)) = join(
        || generate_salt(),
        || join(|| generate_salt(), || generate_salt()),
    );

    // Hash the password
    let mk = generate_hash_mk(&password, &salt1);
    for b in salt1 {
        print!("{:02x}", b);
    }
    println!();

    // Hash the MK and derive the DPK:
    let (hash_mk, dpk) = join(
        || generate_hash_mk(mk.as_bytes(), &salt2),
        || derive_dpk(mk.as_bytes(), &salt3),
    );
    println!("{hash_mk}");
    for b in salt2 {
        print!("{:02x}", b);
    }
    println!();

    println!("{dpk}");
    for b in salt3 {
        print!("{:02x}", b);
    }
    println!();
}

fn verify_password(password: &Vec<u8>, salt1: &[u8], salt2: &[u8], salt3: &[u8], phash: &str) {
    let mk = generate_hash_mk(password, salt1);
    let hash_mk = generate_hash_mk(mk.as_bytes(), salt2);
    if hash_mk == phash {
        println!("Match");
        let dpk = derive_dpk(password, salt3);
        println!("{}", dpk);
    } else {
        println!("Mismatch");
    }
}

fn get_salt(salt: String) -> [u8; 16] {
    let mut s = [0u8; 16];
    for i in 0..16 {
        let byte = u8::from_str_radix(&salt[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hex")
            .unwrap();
        s[i] = byte;
    }

    s
}

fn readpw() -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;

    // Remove trailing newline(s)
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }

    Ok(buf)
}

fn generate_hash_mk(password: &[u8], salt: &[u8]) -> String {
    let params = yescrypt::Params::new_with_all_params(Mode::default(), 2048, 8, 1, 0, 0).unwrap();
    let mk_or_hash = Yescrypt.hash_password_with_params(password, &salt, params);
    format!("{}", mk_or_hash.unwrap().fields().last().unwrap().as_str())
}

fn derive_dpk(password: &[u8], salt: &[u8]) -> String {
    let params =
        yescrypt::Params::new_with_all_params(Mode::default(), 32768, 32, 1, 0, 0).unwrap();
    let hash = Yescrypt.hash_password_with_params(&password, salt, params);
    format!("{}", hash.unwrap().fields().last().unwrap().as_str())
}

fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    match OsRng.try_fill_bytes(&mut salt) {
        Ok(salt) => salt,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    };
    salt
}
