//! The few framework attributes whose integer value is a name or a set of names in the
//! platform's own `attrs.xml`: `installLocation`, `launchMode`, `protectionLevel` and
//! `foregroundServiceType`.
//!
//! Everything else stays a number. That is a choice of this module, not of the file: a
//! binary XML does not carry the attribute's declared type, and no framework table is
//! embedded here, so an attribute not listed below is never given a name it might not
//! have. The names are the public ones from the Android platform; which attributes are
//! named, and how a flag word is spelled, is pinned by the recordings of the reference
//! engine in `artifacts/mdd-072/probe/a0-enums.json`.

const INSTALL_LOCATION: [(u32, &str); 3] =
    [(0, "auto"), (1, "internalOnly"), (2, "preferExternal")];
const LAUNCH_MODE: [(u32, &str); 5] = [
    (0, "standard"),
    (1, "singleTop"),
    (2, "singleTask"),
    (3, "singleInstance"),
    (4, "singleInstancePerTask"),
];
/// `protectionLevel` flag words, highest value first: a flag is named when all of its bits
/// are set in what is left, and its bits are then taken out, so `3` is
/// `signatureOrSystem` and not `dangerous|signature`.
const PROTECTION_LEVEL: [(u32, &str); 26] = [
    (0x0800_0000, "knownSigner"),
    (0x0400_0000, "role"),
    (0x0200_0000, "recents"),
    (0x0100_0000, "retailDemo"),
    (0x0080_0000, "companion"),
    (0x0040_0000, "module"),
    (0x0020_0000, "appPredictor"),
    (0x0010_0000, "incidentReportApprover"),
    (0x0008_0000, "configurator"),
    (0x0001_0000, "textClassifier"),
    (0x8000, "vendorPrivileged"),
    (0x4000, "oem"),
    (0x2000, "runtime"),
    (0x1000, "instant"),
    (0x800, "setup"),
    (0x400, "preinstalled"),
    (0x200, "verifier"),
    (0x100, "installer"),
    (0x80, "pre23"),
    (0x40, "appop"),
    (0x20, "development"),
    (0x10, "privileged"),
    (4, "internal"),
    (3, "signatureOrSystem"),
    (2, "signature"),
    (1, "dangerous"),
];

/// `foregroundServiceType` bits, highest first. The platform's table has grown; this is the one the
/// recordings of the reference engine show (`fileManagement`, 0x1000, is not named there, so a word with
/// only that bit stays a number).
const FOREGROUND_SERVICE_TYPE: [(u32, &str); 14] = [
    (0x4000_0000, "specialUse"),
    (0x2000, "mediaProcessing"),
    (0x800, "shortService"),
    (0x400, "systemExempted"),
    (0x200, "remoteMessaging"),
    (0x100, "health"),
    (0x80, "microphone"),
    (0x40, "camera"),
    (0x20, "mediaProjection"),
    (0x10, "connectedDevice"),
    (8, "location"),
    (4, "phoneCall"),
    (2, "mediaPlayback"),
    (1, "dataSync"),
];

/// The names of the flags set in `data`, highest first and joined by `|`; a flag is named when all of
/// its bits are left, and its bits are then taken out. `None` when nothing is named.
fn flags(table: &[(u32, &str)], data: u32) -> Option<String> {
    let mut left = data;
    let mut names = Vec::new();
    for (flag, name) in table {
        if left & flag == *flag {
            names.push(*name);
            left &= !flag;
        }
    }
    (!names.is_empty()).then(|| names.join("|"))
}

/// The spelling of `data` as the value of the android-namespace attribute `local_name`, when
/// the attribute is one of those above and the word names something; otherwise `None` and
/// the caller writes the number.
pub fn named(local_name: &str, data: u32) -> Option<String> {
    let single = |table: &[(u32, &str)]| {
        table
            .iter()
            .find(|(value, _)| *value == data)
            .map(|(_, name)| (*name).to_owned())
    };
    match local_name {
        "installLocation" => single(&INSTALL_LOCATION),
        "launchMode" => single(&LAUNCH_MODE),
        "protectionLevel" => flags(&PROTECTION_LEVEL, data),
        "foregroundServiceType" => flags(&FOREGROUND_SERVICE_TYPE, data),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerations_name_their_values_and_leave_the_rest_numbers() {
        assert_eq!(named("installLocation", 2).unwrap(), "preferExternal");
        assert_eq!(named("installLocation", 3), None);
        assert_eq!(named("launchMode", 4).unwrap(), "singleInstancePerTask");
        assert_eq!(named("launchMode", 5), None);
        assert_eq!(named("versionCode", 1), None);
    }

    #[test]
    fn foreground_service_type_is_a_flag_word_in_the_order_the_reference_writes_it() {
        assert_eq!(named("foregroundServiceType", 1).unwrap(), "dataSync");
        assert_eq!(
            named("foregroundServiceType", 3).unwrap(),
            "mediaPlayback|dataSync"
        );
        assert_eq!(
            named("foregroundServiceType", 0x42).unwrap(),
            "camera|mediaPlayback"
        );
        assert_eq!(
            named("foregroundServiceType", 0x4000_0000).unwrap(),
            "specialUse"
        );
        // not named in the table: a number, as for any other attribute
        assert_eq!(named("foregroundServiceType", 0), None);
        assert_eq!(named("foregroundServiceType", 0x1000), None);
        assert_eq!(named("foregroundServiceType", 0x8000_0000), None);
        // the named bits are named and the unnamed one is not mentioned
        assert_eq!(
            named("foregroundServiceType", 0x1003).unwrap(),
            "mediaPlayback|dataSync"
        );
    }

    #[test]
    fn protection_level_is_a_flag_word_spelled_high_flag_first() {
        assert_eq!(named("protectionLevel", 0), None);
        assert_eq!(named("protectionLevel", 1).unwrap(), "dangerous");
        assert_eq!(named("protectionLevel", 3).unwrap(), "signatureOrSystem");
        assert_eq!(named("protectionLevel", 4).unwrap(), "internal");
        assert_eq!(
            named("protectionLevel", 0x12).unwrap(),
            "privileged|signature"
        );
        assert_eq!(
            named("protectionLevel", 0x2002).unwrap(),
            "runtime|signature"
        );
        assert_eq!(
            named("protectionLevel", 0x1_0010).unwrap(),
            "textClassifier|privileged"
        );
        // no flag has these bits
        assert_eq!(named("protectionLevel", 8), None);
        assert_eq!(named("protectionLevel", 0x2_0000), None);
        assert_eq!(named("protectionLevel", 0x8000_0000), None);
        // every named bit at once: the unnamed bits are not mentioned
        let all = named("protectionLevel", u32::MAX).unwrap();
        assert!(all.starts_with("knownSigner|role|"));
        assert!(all.ends_with("|privileged|internal|signatureOrSystem"));
    }
}
