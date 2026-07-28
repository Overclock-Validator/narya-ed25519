use ed25519_dalek_v1::{PublicKey as PrecompilePublicKey, Signature as PrecompileSignature};
use serde::Deserialize;
use solana_signature::Signature as TransactionSignature;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

#[derive(Deserialize)]
struct OracleCase {
    name: String,
    public_key: String,
    message: String,
    signature: String,
    narya_dalek_strict: bool,
}

fn decode_exact<const N: usize>(label: &str, encoded: &str) -> Result<[u8; N], Box<dyn Error>> {
    let decoded = hex::decode(encoded)?;
    decoded
        .try_into()
        .map_err(|value: Vec<u8>| format!("{label}: got {} bytes, want {N}", value.len()).into())
}

// transaction_verdict follows Agave v4's transaction call path:
// perf::sigverify -> solana_signature::Signature::verify.  Pinning the wrapper
// crate matters as much as pinning dalek because this is the API Agave calls.
fn transaction_verdict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let signature = TransactionSignature::from(*signature);
    signature.verify(public_key, message)
}

// precompile_verdict follows Agave v4's separate Ed25519-precompile path,
// which directly calls ed25519-dalek 1.0.1 PublicKey::verify_strict.  It is a
// compatibility oracle, not Narya's transaction-verification contract.
fn precompile_verdict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(public_key) = PrecompilePublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = PrecompileSignature::from_bytes(signature) else {
        return false;
    };
    public_key.verify_strict(message, &signature).is_ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let corpus_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: narya-agave-v4-oracle <corpus.jsonl>")?;
    let corpus = BufReader::new(File::open(&corpus_path)?);

    let mut cases = 0usize;
    let mut transaction_mismatches = Vec::new();
    let mut precompile_differences = Vec::new();
    for (line_number, line) in corpus.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let item: OracleCase = serde_json::from_str(&line)
            .map_err(|error| format!("{}:{}: {error}", corpus_path.display(), line_number + 1))?;
        let public_key = decode_exact::<32>(&item.name, &item.public_key)?;
        let message = hex::decode(&item.message)?;
        let signature = decode_exact::<64>(&item.name, &item.signature)?;

        let transaction = transaction_verdict(&public_key, &message, &signature);
        let precompile = precompile_verdict(&public_key, &message, &signature);
        if transaction != item.narya_dalek_strict {
            transaction_mismatches.push(format!(
                "{}: Agave-v4-transaction={} Narya-DalekStrict={}",
                item.name, transaction, item.narya_dalek_strict
            ));
        }
        if precompile != transaction {
            precompile_differences.push(format!(
                "{}: precompile-v1={} transaction-v2={}",
                item.name, precompile, transaction
            ));
        }
        cases += 1;
    }

    println!("Agave v4 oracle corpus: {cases} cases");
    println!(
        "transaction-vs-Narya mismatches: {}",
        transaction_mismatches.len()
    );
    println!(
        "precompile-vs-transaction differences: {}",
        precompile_differences.len()
    );
    for difference in precompile_differences.iter().take(20) {
        println!("precompile difference: {difference}");
    }
    if precompile_differences.len() > 20 {
        println!(
            "precompile differences omitted: {}",
            precompile_differences.len() - 20
        );
    }
    if !transaction_mismatches.is_empty() {
        for mismatch in &transaction_mismatches {
            eprintln!("transaction mismatch: {mismatch}");
        }
        return Err(format!(
            "{} Agave v4 transaction verdicts differ from Narya",
            transaction_mismatches.len()
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_vector_1_is_accepted_by_both_v4_paths() {
        let public_key = decode_exact::<32>(
            "RFC8032-1 public key",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let signature = decode_exact::<64>(
            "RFC8032-1 signature",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        assert!(transaction_verdict(&public_key, &[], &signature));
        assert!(precompile_verdict(&public_key, &[], &signature));
    }

    #[test]
    fn cctv_small_order_r_is_rejected_by_both_v4_paths() {
        let public_key = decode_exact::<32>(
            "CCTV public key",
            "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        )
        .unwrap();
        let signature = decode_exact::<64>(
            "CCTV signature",
            "00000000000000000000000000000000000000000000000000000000000000009472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09",
        )
        .unwrap();
        let message = b"ed25519vectors 3";
        assert!(!transaction_verdict(&public_key, message, &signature));
        assert!(!precompile_verdict(&public_key, message, &signature));
    }
}
