use semver::Version;

/// Parse a raw Kubernetes gitVersion string (e.g. "v1.29.1-gke.3") into semver.
/// Strips leading 'v' and any cloud-provider suffixes.
pub fn parse_k8s_version(raw: &str) -> Option<Version> {
    let s = raw.trim_start_matches('v');
    // Strip at first '-' or '+' (pre-release / build metadata / cloud suffix)
    let core = if let Some(i) = s.find(['-', '+']) {
        &s[..i]
    } else {
        s
    };
    Version::parse(core).ok()
}

/// Check whether `version` falls within any of the given `[min, max)` pairs.
pub fn in_affected_range(version: &Version, ranges: &[(&str, &str)]) -> bool {
    for (lo, hi) in ranges {
        let lo_v = match Version::parse(lo) { Ok(v) => v, Err(_) => continue };
        let hi_v = match Version::parse(hi) { Ok(v) => v, Err(_) => continue };
        if *version >= lo_v && *version < hi_v {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain() {
        let v = parse_k8s_version("v1.29.1").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 29);
    }

    #[test]
    fn test_parse_gke() {
        let v = parse_k8s_version("v1.28.4-gke.5").unwrap();
        assert_eq!(v.minor, 28);
    }

    #[test]
    fn test_range() {
        let v = Version::parse("1.10.10").unwrap();
        assert!(in_affected_range(&v, &[("1.0.0", "1.10.11")]));
        let v2 = Version::parse("1.10.11").unwrap();
        assert!(!in_affected_range(&v2, &[("1.0.0", "1.10.11")]));
    }
}
