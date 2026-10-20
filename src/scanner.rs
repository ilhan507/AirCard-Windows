use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use regex::Regex;

use crate::device::ActiveDeviceSession;

#[cfg(windows)]
unsafe extern "system" {
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const i8, optlen: i32) -> i32;
}

#[cfg(windows)]
const SOL_SOCKET: i32 = 0xffff;
#[cfg(windows)]
const SO_RCVTIMEO: i32 = 0x1006;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SavedCard {
    pub hash: String,
    pub name: String,
    #[serde(default)]
    pub last_image: Option<String>,
}

pub fn get_cards_storage_path() -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| r"C:\Users\Default\AppData\Local".to_string());
    let dir = PathBuf::from(local_app_data).join("AirCard");
    let _ = fs::create_dir_all(&dir);
    dir.join("cards.json")
}

pub fn is_valid_card_hash(h: &str) -> bool {
    let trimmed = h.trim().trim_matches(['\'', '"', '.', ',']).trim();
    let len = trimmed.len();
    // Real Apple Wallet card hashes are SHA-1 (27-28 chars) or SHA-256 (43-44 chars)
    if len != 27 && len != 28 && len != 43 && len != 44 {
        return false;
    }

    // Must be base64 alphabet characters (URL-safe included). Hyphen/underscore
    // count is not a garbage heuristic — real IDs can contain several of each.
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_' || c == '=') {
        return false;
    }

    // Reject obvious system identifiers, bundle IDs and common keywords
    let lower = trimmed.to_lowercase();
    if lower.contains("mobileasset")
        || lower.contains("com_apple")
        || lower.contains("com.")
        || lower.contains("apple.")
        || lower.contains("curtain")
        || lower.contains("binder")
        || lower.contains("optimizer")
        || lower.contains("system")
        || lower.contains("uaf")
        || lower.contains("siri")
        || lower.contains("dialog")
        || lower.contains("planner")
        || lower.contains("linguistic")
        || lower.contains("timing")
        || lower.contains("model")
        || lower.contains("translation")
        || lower.contains("visual")
        || lower.contains("device")
        || lower.contains("override")
        || lower.contains("motion")
        || lower.contains("search")
    {
        return false;
    }

    // '=' can only appear at the end
    if let Some(pos) = trimmed.find('=') {
        if pos < len - 2 {
            return false;
        }
    }

    // Normalize URL-safe base64 and pad
    let mut b64 = trimmed.replace('-', "+").replace('_', "/");
    while b64.len() % 4 != 0 {
        b64.push('=');
    }

    use base64::Engine;
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&b64) {
        // Must be exactly 20 bytes (SHA-1) or 32 bytes (SHA-256)
        if decoded.len() == 20 || decoded.len() == 32 {
            // Reject trivial all-identical bytes
            if decoded.iter().all(|&b| b == decoded[0]) {
                return false;
            }

            // Cryptographic hashes have high byte entropy:
            // 1. Must contain both bytes with MSB set (>= 128) and MSB clear (< 128).
            let has_high = decoded.iter().any(|&b| b >= 128);
            let has_low = decoded.iter().any(|&b| b < 128);
            if !has_high || !has_low {
                return false;
            }

            // 2. Must contain at least 12 distinct byte values in 20 bytes
            let mut unique_bytes = std::collections::HashSet::new();
            for &b in &decoded {
                unique_bytes.insert(b);
            }
            if unique_bytes.len() < 12 {
                return false;
            }

            if DUMMY_HASHES.contains(&trimmed) || DUMMY_HASHES.iter().any(|d| d.trim_end_matches('=') == trimmed) {
                return false;
            }
            return true;
        }
    }

    false
}

pub fn load_saved_cards() -> Vec<SavedCard> {
    let path = get_cards_storage_path();
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(cards) = serde_json::from_str::<Vec<SavedCard>>(&content) {
            let valid_cards: Vec<SavedCard> = cards.into_iter().filter(|c| is_valid_card_hash(&c.hash)).collect();
            // Automatically purge corrupted or garbage entries from disk
            save_saved_cards(&valid_cards);
            return valid_cards;
        }
    }
    Vec::new()
}

pub fn save_saved_cards(cards: &[SavedCard]) {
    let path = get_cards_storage_path();
    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for c in cards {
        if is_valid_card_hash(&c.hash) && seen.insert(c.hash.clone()) {
            unique.push(c.clone());
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(&unique) {
        let _ = fs::write(path, json);
    }
}

pub fn add_or_update_card(hash: &str, name: &str) {
    if !is_valid_card_hash(hash) {
        return;
    }
    let mut cards = load_saved_cards();
    if let Some(existing) = cards.iter_mut().find(|c| c.hash == hash) {
        if !name.is_empty() && (existing.name.is_empty() || existing.name.starts_with("Card ")) {
            existing.name = name.to_string();
        }
    } else {
        cards.push(SavedCard {
            hash: hash.to_string(),
            name: if name.is_empty() {
                format!("Card {}", cards.len() + 1)
            } else {
                name.to_string()
            },
            last_image: None,
        });
    }
    save_saved_cards(&cards);
}

pub fn rename_card(hash: &str, name: &str) {
    if !is_valid_card_hash(hash) || name.trim().is_empty() {
        return;
    }
    let mut cards = load_saved_cards();
    if let Some(existing) = cards.iter_mut().find(|c| c.hash == hash) {
        existing.name = name.trim().to_string();
        save_saved_cards(&cards);
    }
}

pub fn set_card_last_image(hash: &str, path: &std::path::Path) {
    if !is_valid_card_hash(hash) {
        return;
    }
    let mut cards = load_saved_cards();
    if let Some(existing) = cards.iter_mut().find(|c| c.hash == hash) {
        existing.last_image = Some(path.to_string_lossy().into_owned());
    } else {
        cards.push(SavedCard {
            hash: hash.to_string(),
            name: format!("Card {}", cards.len() + 1),
            last_image: Some(path.to_string_lossy().into_owned()),
        });
    }
    save_saved_cards(&cards);
}

const WALLET_KEYWORDS: &[&str] = &[
    "passd",
    "passbook",
    "passkit",
    "stockholm",
    "nanopassd",
    "npkcompanion",
    "wallet",
    "nfcd",
    "passids",
    "/cards/",
    "/passes/",
];

const DUMMY_HASHES: &[&str] = &[
    "M6nDwZrkYbFlsodLgCbvyFZQ1cc=",
    "kJL-D0rr-SZhbj2c8nK-OQ9hCMY=",
    "hwAtAmHKYwsQrJbT5cTNDsaxVME=",
];

use std::sync::LazyLock;

static DESC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:description|localizedDescription|passName|title)\s*[:=]\s*['"]([^'"]+)['"]"#)
        .unwrap()
});

static CARD_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"/(?:Cards|Passes/Cards)/([A-Za-z0-9+/=_-]{27,44})(?:\.pkpass|\.cache|\.pkcache|/|\s|\x22|'|\)|,|$)").unwrap(),
        Regex::new(r"/([A-Za-z0-9+/=_-]{27,44})\.(?:pkpass|cache|pkcache)").unwrap(),
        Regex::new(r"(?:^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{27}=)(?:$|[^A-Za-z0-9+/_-])").unwrap(),
        Regex::new(r"(?i)(?:card[_\s]?(?:hash|id)|pass[_\s]?(?:hash|id)|unique[_\s]?id)\s*[:=]\s*['\x22]?([A-Za-z0-9+=_-]{27,44})").unwrap(),
        Regex::new(r"(?i)Dashboard loading[^:]*:\s*for\s+([A-Za-z0-9+/=_-]{20,80})(?:[,\s\x22'\)]|$)").unwrap(),
        Regex::new(r"(?i)Dashboard loading[^:]*:\s+([A-Za-z0-9+/=_-]{20,80})\s+-").unwrap(),
    ]
});

static PASS_IDS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)passIDs\[(?:InSession|global)\]\s*:\s*(?:\{\s*)?\(([^)]*)\)").unwrap()
});

fn normalize_extracted_hash(raw: &str) -> Option<String> {
    let h = raw.trim().trim_matches(['\'', '"', '.', ',', '(', ')']);
    if !is_valid_card_hash(h) {
        return None;
    }
    let mut norm = h.to_string();
    if norm.len() == 27 {
        norm.push('=');
    }
    Some(norm)
}

pub fn extract_card_hashes_from_line(line: &str) -> Vec<String> {
    let lower = line.to_lowercase();
    let has_wallet = WALLET_KEYWORDS.iter().any(|k| lower.contains(k));
    if !has_wallet {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for caps in PASS_IDS_RE.captures_iter(line) {
        if let Some(list) = caps.get(1) {
            for token in list.as_str().split(|c: char| {
                c == ',' || c == '"' || c == '\'' || c.is_whitespace()
            }) {
                if let Some(hash) = normalize_extracted_hash(token)
                    && seen.insert(hash.clone())
                {
                    out.push(hash);
                }
            }
        }
    }

    for r in CARD_REGEXES.iter() {
        for caps in r.captures_iter(line) {
            if let Some(m) = caps.get(1)
                && let Some(hash) = normalize_extracted_hash(m.as_str())
                && seen.insert(hash.clone())
            {
                out.push(hash);
            }
        }
    }

    out
}

pub fn extract_card_name_from_line(line: &str) -> Option<String> {
    if let Some(caps) = DESC_RE.captures(line) {
        if let Some(m) = caps.get(1) {
            let name = m.as_str().trim();
            if name.len() > 1 && !name.to_lowercase().contains("<private>") {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
pub fn extract_card_hash_from_line(line: &str) -> Option<String> {
    extract_card_hashes_from_line(line).into_iter().next()
}

pub fn scan_syslog_for_cards<F, L>(
    udid: Option<&str>,
    stop_flag: Arc<AtomicBool>,
    mut on_card_found: F,
    mut log: L,
) -> Result<()>
where
    F: FnMut(String, String),
    L: FnMut(String),
{
    log("Connecting to device session for log monitoring...".to_string());
    let session = ActiveDeviceSession::open(udid)
        .context("Failed to connect to device for log scanning")?;
    let libs = &session.libs;

    log(format!(
        "Starting {} service on device...",
        crate::os_trace::OS_TRACE_SERVICE
    ));
    let service_conn = session
        .start_service(crate::os_trace::OS_TRACE_SERVICE)
        .with_context(|| {
            format!(
                "Failed to start {} service (unified device log)",
                crate::os_trace::OS_TRACE_SERVICE
            )
        })?;

    // Read frames through the service connection (AMDServiceConnectionReceive)
    // so secure sessions work too. A socket receive timeout keeps Stop
    // responsive on plaintext streams; sockets wrapped in TLS are left alone.
    #[cfg(windows)]
    unsafe {
        let io_ctx = (libs.amd_service_connection_get_secure_io_context)(service_conn);
        if io_ctx.is_null() {
            let raw_socket = (libs.amd_service_connection_get_socket)(service_conn);
            if raw_socket > 0 {
                let timeout_ms: u32 = 500;
                setsockopt(
                    raw_socket as usize,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &timeout_ms as *const u32 as *const i8,
                    std::mem::size_of::<u32>() as i32,
                );
            }
        }
    }

    // Start the unified activity stream via Apple's own plist sender so the
    // message framing matches whatever this MobileDevice build expects.
    log("Requesting unified log activity stream (StartActivity)...".to_string());
    let request = crate::os_trace::start_activity_request();
    let mut request_bytes = Vec::new();
    plist::to_writer_binary(&mut request_bytes, &request)
        .context("Failed to serialize StartActivity request")?;
    let cf_request = libs.create_cf_plist_from_bytes(&request_bytes)?;
    let send_status = unsafe {
        (libs.amd_service_connection_send_message)(
            service_conn,
            cf_request.raw,
            crate::apple::K_CFPROPERTY_LIST_BINARY_FORMAT_V1_0,
        )
    };
    if send_status != 0 {
        unsafe {
            (libs.amd_service_connection_invalidate)(service_conn);
        }
        anyhow::bail!(
            "AMDServiceConnectionSendMessage(StartActivity) failed with code {}",
            send_status
        );
    }

    let mut reader = crate::os_trace::FrameReader::new(
        |buf: &mut [u8]| -> i32 {
            unsafe {
                (libs.amd_service_connection_receive)(
                    service_conn,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            }
        },
        || stop_flag.load(Ordering::Relaxed),
    );

    let reply = match reader.read_plist_frame() {
        Ok(reply) => reply,
        Err(e) => {
            unsafe {
                (libs.amd_service_connection_invalidate)(service_conn);
            }
            anyhow::bail!("Device did not acknowledge log streaming: {e}");
        }
    };
    let reply_dict = reply.as_dictionary();
    let status = reply_dict
        .and_then(|d| d.get("Status"))
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    if status != "RequestSuccessful" {
        let detail = reply_dict
            .and_then(|d| d.get("Error"))
            .and_then(|v| v.as_string())
            .unwrap_or("no error details provided");
        unsafe {
            (libs.amd_service_connection_invalidate)(service_conn);
        }
        anyhow::bail!(
            "Device refused unified log streaming (Status: {status}, Error: {detail})"
        );
    }

    log("Connected to the unified device log stream. Listening for Wallet & PassKit events...".to_string());
    log("Tip: Open Apple Wallet on your iPhone or tap your card to trigger events.".to_string());

    while !stop_flag.load(Ordering::Relaxed) {
        let (frame_type, payload) = match reader.read_frame() {
            Ok(frame) => frame,
            Err(crate::os_trace::FrameError::Interrupted) => break,
            Err(e) => {
                log(format!("Unified log stream ended: {e}"));
                break;
            }
        };
        if frame_type != crate::os_trace::FRAME_ACTIVITY {
            continue;
        }
        let Some(record) = crate::os_trace::parse_activity_record(&payload) else {
            continue;
        };
        // Multiline messages are preserved: CoreFoundation resource lookup
        // logs expose Wallet .pkpass paths on a continuation line.
        for line in crate::os_trace::format_activity_line(&record).split('\n') {
            let name = extract_card_name_from_line(line).unwrap_or_default();
            for hash in extract_card_hashes_from_line(line) {
                log(format!(
                    "Found card pass! Name: '{}', Hash: {}",
                    if name.is_empty() { "Unknown" } else { &name },
                    hash
                ));
                add_or_update_card(&hash, &name);
                on_card_found(hash, name.clone());
            }
        }
    }

    unsafe {
        (libs.amd_service_connection_invalidate)(service_conn);
    }
    log("Log scan stopped.".to_string());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_card_hash() {
        let line1 = "passd[123]: Card hash: 'OM6NYhwXMZrAw0sRUjR62wmF4ZQ=' loaded";
        assert_eq!(
            extract_card_hash_from_line(line1),
            Some("OM6NYhwXMZrAw0sRUjR62wmF4ZQ=".to_string())
        );

        let line2 = "nanopassd: Accessing /var/mobile/Library/Passes/Cards/d64fKk0kyHWP11IWV2GRLud4XQk.pkpass";
        assert_eq!(
            extract_card_hash_from_line(line2),
            Some("d64fKk0kyHWP11IWV2GRLud4XQk=".to_string())
        );

        let line3 = "passd: Accessing /var/mobile/Library/Passes/Cards/c5g3sMLJHXE63-5NVq-aZE81M-s=.pkpass";
        assert_eq!(
            extract_card_hash_from_line(line3),
            Some("c5g3sMLJHXE63-5NVq-aZE81M-s=".to_string())
        );

        let dashboard = "Passbook(PassKitUI): Dashboard loading (...): for OM6NYhwXMZrAw0sRUjR62wmF4ZQ=, pass feature unknown";
        assert_eq!(
            extract_card_hash_from_line(dashboard),
            Some("OM6NYhwXMZrAw0sRUjR62wmF4ZQ=".to_string())
        );

        let dashboard2 = "Passbook(PassKitUI): Dashboard loading (...): d64fKk0kyHWP11IWV2GRLud4XQk= - m:NO, sm:NO";
        assert_eq!(
            extract_card_hash_from_line(dashboard2),
            Some("d64fKk0kyHWP11IWV2GRLud4XQk=".to_string())
        );

        let nfc = r#"nfcd: passIDs[InSession]: {("OM6NYhwXMZrAw0sRUjR62wmF4ZQ=")} passIDs[global]: {("d64fKk0kyHWP11IWV2GRLud4XQk=")}"#;
        assert_eq!(
            extract_card_hashes_from_line(nfc),
            vec![
                "OM6NYhwXMZrAw0sRUjR62wmF4ZQ=".to_string(),
                "d64fKk0kyHWP11IWV2GRLud4XQk=".to_string(),
            ]
        );

        // Dummy/unrelated lines should be ignored
        let dummy = "passd: Using dummy hash hwAtAmHKYwsQrJbT5cTNDsaxVME=";
        assert_eq!(extract_card_hash_from_line(dummy), None);
    }

    #[test]
    fn test_extract_card_name() {
        let line = "passd[456]: Pass with localizedDescription = 'Apple Card' updated";
        assert_eq!(
            extract_card_name_from_line(line),
            Some("Apple Card".to_string())
        );
    }

    #[test]
    fn test_is_valid_card_hash() {
        // Real card hashes
        assert!(is_valid_card_hash("OM6NYhwXMZrAw0sRUjR62wmF4ZQ="));
        assert!(is_valid_card_hash("d64fKk0kyHWP11IWV2GRLud4XQk="));
        assert!(is_valid_card_hash("d64fKk0kyHWP11IWV2GRLud4XQk"));
        assert!(is_valid_card_hash("  OM6NYhwXMZrAw0sRUjR62wmF4ZQ=  "));
        assert!(is_valid_card_hash("'OM6NYhwXMZrAw0sRUjR62wmF4ZQ=' "));
        assert!(is_valid_card_hash(" \"OM6NYhwXMZrAw0sRUjR62wmF4ZQ=\", "));
        // URL-safe IDs with three hyphens (rejected by the old count heuristic).
        assert!(is_valid_card_hash("c5g3sMLJHXE63-5NVq-aZE81M-s="));
        assert!(!is_valid_card_hash("kJL-D0rr-SZhbj2c8nK-OQ9hCMY="));

        // System garbage strings that must be rejected
        let garbage = [
            "PresentationBinderIndirectAccessHosting-",
            "SB-systemApertureCurtain",
            "com_apple_MobileAsset_UAF_Translation_Assets",
            "com_apple_MobileAsset_UAF_FM_Visual",
            "com_apple_MobileAsset_UAF_DeviceCheck",
            "com_apple_MobileAsset_UAF_Siri_TextToSpeech",
            "com_apple_MobileAsset_UAF_Siri_DialogAssets",
            "com_apple_MobileAsset_UAF_IF_Planner",
            "SubscriptionOptimizerTimingModels",
            "com_apple_MobileAsset_UAF_LinguisticData",
            "com_apple_MobileAsset_UAF_FM_Overrides",
            "com_apple_MobileAsset_UAF_Siri_Understanding",
            "com_apple_MobileAsset_UAF_MotionAnomalyFM",
            "com_apple_MobileAsset_UAF_TKModelMessages",
            "com_apple_MobileAsset_UAF_Search_ODLA",
        ];

        for g in garbage {
            assert!(!is_valid_card_hash(g), "Expected {} to be rejected as card hash", g);
        }
    }

    #[test]
    fn test_saved_cards_purging() {
        let loaded = load_saved_cards();
        for card in &loaded {
            assert!(is_valid_card_hash(&card.hash), "Invalid hash was not purged: {}", card.hash);
        }
    }

    #[test]
    fn test_os_trace_service_handshake() {
        let session = match ActiveDeviceSession::open(None) {
            Ok(s) => s,
            Err(e) => {
                println!("No device connected: {:?}", e);
                return;
            }
        };
        let libs = &session.libs;
        let conn = session
            .start_service(crate::os_trace::OS_TRACE_SERVICE)
            .expect("start os_trace_relay");

        let request = crate::os_trace::start_activity_request();
        let mut request_bytes = Vec::new();
        plist::to_writer_binary(&mut request_bytes, &request).expect("serialize request");
        let cf_request = libs.create_cf_plist_from_bytes(&request_bytes).expect("cf plist");
        let send_status = unsafe {
            (libs.amd_service_connection_send_message)(
                conn,
                cf_request.raw,
                crate::apple::K_CFPROPERTY_LIST_BINARY_FORMAT_V1_0,
            )
        };
        println!("AMDServiceConnectionSendMessage(StartActivity): {}", send_status);

        let mut reader = crate::os_trace::FrameReader::new(
            |buf: &mut [u8]| -> i32 {
                unsafe { (libs.amd_service_connection_receive)(conn, buf.as_mut_ptr(), buf.len()) }
            },
            || false,
        );
        match reader.read_plist_frame() {
            Ok(reply) => println!("StartActivity reply: {:?}", reply),
            Err(e) => println!("No reply from device: {e}"),
        }
        unsafe { (libs.amd_service_connection_invalidate)(conn) };
    }
}
