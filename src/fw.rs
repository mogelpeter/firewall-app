//! Windows Firewall access through the INetFwPolicy2 COM API (no PowerShell).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{S_OK, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;

pub const RULE_PREFIX: &str = "PSFirewallBlock_";

pub type Result<T> = std::result::Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Keeps COM initialised on the current thread for as long as it lives.
pub struct ComGuard(bool);

impl ComGuard {
    pub fn new() -> Self {
        // S_FALSE (already initialised) also needs a matching CoUninitialize.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        ComGuard(hr.is_ok())
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() }
        }
    }
}

/// One program that has at least one rule created by this tool.
#[derive(Clone, Debug)]
pub struct BlockedProgram {
    pub path: String,
    pub name: String,
    pub inbound: bool,
    pub outbound: bool,
    pub enabled: bool,
    pub exists: bool,
    /// false when remembered but currently without any firewall rule
    pub active_rules: bool,
}

#[derive(Default, Debug, Clone)]
pub struct BlockReport {
    pub blocked: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub struct RemoveReport {
    pub removed: usize,
    pub errors: Vec<String>,
}

/// Case-insensitive key for comparing Windows paths. `%VAR%` parts (used by many firewall rules)
/// are expanded, so both spellings of a path compare equal.
pub fn path_key(p: &str) -> String {
    expand_env(p.trim()).replace('/', "\\").to_lowercase()
}

fn expand_env(p: &str) -> String {
    let mut out = String::new();
    let mut rest = p;
    while let Some(a) = rest.find('%') {
        let Some(len) = rest[a + 1..].find('%') else { break };
        match std::env::var(&rest[a + 1..a + 1 + len]) {
            Ok(v) => {
                out.push_str(&rest[..a]);
                out.push_str(&v);
                rest = &rest[a + len + 2..];
            }
            Err(_) => {
                out.push_str(&rest[..a + 1]);
                rest = &rest[a + 1..];
            }
        }
    }
    out + rest
}

/// The folder a program lives in, used to group its executables: the first folder below a known
/// install location (Program Files, AppData, Steam library, ...), otherwise the folder holding
/// the exe, skipping technical subfolders such as `bin\x64`.
pub fn program_dir(path: &str) -> String {
    const HOLDERS: [&str; 6] = ["program files", "program files (x86)", "programdata", "games", "xboxgames", "epic games"];
    const TECHNICAL: [&str; 8] = ["bin", "bin32", "bin64", "binaries", "win32", "win64", "x64", "x86"];
    let norm = path.replace('/', "\\");
    let mut dirs: Vec<&str> = norm.split('\\').collect();
    dirs.pop(); // file name
    let is = |i: usize, name: &str| dirs.get(i).is_some_and(|d| d.eq_ignore_ascii_case(name));
    let mut end = None;
    for i in 0..dirs.len() {
        let skip = if is(i, "steamapps") && is(i + 1, "common") {
            2
        } else if is(i, "appdata") {
            if is(i + 2, "programs") { 3 } else { 2 }
        } else if HOLDERS.iter().any(|h| is(i, h)) {
            1
        } else {
            continue;
        };
        let mut j = i + skip;
        if is(j, "common files") {
            j += 1;
        }
        if j < dirs.len() {
            end = Some(j + 1); // a deeper match wins (Steam inside Program Files)
        }
    }
    let end = end.unwrap_or_else(|| {
        let mut e = dirs.len();
        while e > 1 && TECHNICAL.iter().any(|t| is(e - 1, t)) {
            e -= 1;
        }
        e
    });
    dirs[..end].join("\\")
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Rule name unique per full path, so same-named exes in different folders never share a name.
pub fn rule_name(path: &str, inbound: bool) -> String {
    let stem = Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base: String = stem
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    format!(
        "{RULE_PREFIX}{base}_{:08x}_{}",
        fnv1a(&path_key(path)) as u32,
        if inbound { "Inbound" } else { "Outbound" }
    )
}

struct RawRule {
    name: String,
    app: String,
    inbound: bool,
    enabled: bool,
    /// created by this app
    ours: bool,
}

/// Which (path key, inbound) pairs already have a block rule; the value says whether one is enabled.
pub type Coverage = HashMap<(String, bool), bool>;

fn coverage_of(live: &[RawRule]) -> Coverage {
    let mut c = Coverage::new();
    for r in live {
        *c.entry((path_key(&r.app), r.inbound)).or_default() |= r.enabled;
    }
    c
}

/// True when the program already has a block rule in both directions.
pub fn is_blocked(c: &Coverage, path: &str) -> bool {
    let key = path_key(path);
    [true, false].iter().all(|&inbound| c.contains_key(&(key.clone(), inbound)))
}

fn policy() -> Result<INetFwPolicy2> {
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(err)
}

/// True when a rule made elsewhere blocks the program completely: enabled, every profile,
/// protocol, port, address and interface type, and not limited to a service.
fn blocks_everything(rule: &INetFwRule) -> bool {
    let any = |v: windows::core::Result<BSTR>| {
        v.map(|s| {
            let s = s.to_string();
            s.is_empty() || s == "*" || s.eq_ignore_ascii_case("all")
        })
        .unwrap_or(false)
    };
    let all = NET_FW_PROFILE2_DOMAIN.0 | NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0;
    unsafe {
        rule.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK)
            && rule.Enabled().is_ok_and(|b| b == VARIANT_TRUE)
            && rule.Protocol().is_ok_and(|p| p == NET_FW_IP_PROTOCOL_ANY.0)
            && rule.Profiles().is_ok_and(|p| p & all == all)
            && any(rule.LocalPorts())
            && any(rule.RemotePorts())
            && any(rule.LocalAddresses())
            && any(rule.RemoteAddresses())
            && any(rule.InterfaceTypes())
            && any(rule.ServiceName())
    }
}

/// Reads every rule that carries our prefix, plus rules from other sources that already block a
/// program completely.
fn read_rules(rules: &INetFwRules) -> Result<Vec<RawRule>> {
    let unk = unsafe { rules._NewEnum() }.map_err(err)?;
    let en: IEnumVARIANT = unk.cast().map_err(err)?;
    let mut out = Vec::new();
    loop {
        let mut batch: Vec<VARIANT> = (0..64).map(|_| VARIANT::default()).collect();
        let mut fetched = 0u32;
        let hr = unsafe { en.Next(&mut batch, &mut fetched) };
        if fetched == 0 {
            break;
        }
        for v in batch.iter().take(fetched as usize) {
            let Ok(disp) = IDispatch::try_from(v) else { continue };
            let Ok(rule) = disp.cast::<INetFwRule>() else { continue };
            let Ok(name) = (unsafe { rule.Name() }) else { continue };
            let name = name.to_string();
            let ours = name.starts_with(RULE_PREFIX);
            if !ours && !blocks_everything(&rule) {
                continue;
            }
            let app = unsafe { rule.ApplicationName() }.map(|b| b.to_string()).unwrap_or_default();
            if !ours && app.is_empty() {
                continue;
            }
            let inbound = unsafe { rule.Direction() }.map(|d| d == NET_FW_RULE_DIR_IN).unwrap_or(false);
            let enabled = unsafe { rule.Enabled() }.map(|b| b == VARIANT_TRUE).unwrap_or(false);
            out.push(RawRule { name, app, inbound, enabled, ours });
        }
        if hr != S_OK {
            break;
        }
    }
    Ok(out)
}


// ---- persistent list --------------------------------------------------------
// The firewall is the source of truth, but we also remember every blocked program in
// %ProgramFiles%\FirewallManager\blocked.txt (admin-only folder) so the list survives updates, reinstalls and
// rules that get wiped, and can be restored.

/// Only absolute `.exe` paths are accepted from the saved list.
fn valid_entry(l: &str) -> bool {
    let p = Path::new(l);
    !l.is_empty()
        && p.is_absolute()
        && p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
}

/// Store folder under %ProgramFiles%, where only administrators can create or change anything
/// (inherited default ACL), so no user-controlled folder, junction or file can pre-exist.
/// No ACLs are rewritten. Reparse points are refused.
pub fn secure_dir() -> Option<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    // Known-folder API instead of environment variables (user environment can be overridden).
    let root = unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.as_ptr() as *const _));
        PathBuf::from(s?)
    };
    let d = root.join("FirewallManager");
    std::fs::create_dir_all(&d).ok()?;
    const REPARSE: u32 = 0x400;
    if std::fs::symlink_metadata(&d).ok()?.file_attributes() & REPARSE != 0 {
        return None;
    }
    Some(d)
}

fn store_load() -> Vec<String> {
    let Some(d) = secure_dir() else { return vec![] };
    // blocked.bak is the previous good copy, used if blocked.txt is missing or damaged
    let text = std::fs::read_to_string(d.join("blocked.txt"))
        .or_else(|_| std::fs::read_to_string(d.join("blocked.bak")))
        .unwrap_or_default();
    let mut seen = HashSet::new();
    text.lines()
        .map(|l| l.trim())
        .filter(|l| valid_entry(l) && seen.insert(path_key(l)))
        .map(String::from)
        .collect()
}

fn store_save(paths: &[String]) {
    let Some(d) = secure_dir() else { return };
    let (f, bak, tmp) = (d.join("blocked.txt"), d.join("blocked.bak"), d.join("blocked.tmp"));
    if std::fs::write(&tmp, paths.join("
")).is_ok() {
        if f.is_file() {
            let _ = std::fs::copy(&f, &bak);
        }
        let _ = std::fs::rename(&tmp, &f);
    }
}

fn store_add(new: &[String]) {
    let mut cur = store_load();
    let mut keys: HashSet<String> = cur.iter().map(|p| path_key(p)).collect();
    let before = cur.len();
    for p in new {
        if keys.insert(path_key(p)) {
            cur.push(p.clone());
        }
    }
    if cur.len() != before {
        store_save(&cur);
    }
}

fn store_remove(keys: Option<&HashSet<String>>) {
    match keys {
        None => store_save(&[]),
        Some(k) => {
            let cur = store_load();
            let kept: Vec<String> = cur.iter().filter(|p| !k.contains(&path_key(p))).cloned().collect();
            if kept.len() != cur.len() {
                store_save(&kept);
            }
        }
    }
}

/// Re-creates any missing rule (either direction) for every remembered program.
/// Returns how many rules were created.
pub fn restore_missing() -> Result<usize> {
    let _com = ComGuard::new();
    let pol = policy()?;
    let rules = unsafe { pol.Rules() }.map_err(err)?;
    let live = read_rules(&rules)?;
    let mut have = coverage_of(&live);
    // adopt rules from older versions
    store_add(&live.iter().filter(|r| r.ours).map(|r| r.app.clone()).collect::<Vec<_>>());
    let mut n = 0;
    for p in store_load() {
        for inbound in [true, false] {
            let k = (path_key(&p), inbound);
            if !have.contains_key(&k) && Path::new(&p).is_file() && add_rule(&rules, &p, inbound).is_ok() {
                have.insert(k, true);
                n += 1;
            }
        }
    }
    Ok(n)
}

/// All programs blocked by this tool, sorted by name.
pub fn list_blocked() -> Result<Vec<BlockedProgram>> {
    let _com = ComGuard::new();
    let pol = policy()?;
    let rules = unsafe { pol.Rules() }.map_err(err)?;
    let mut map: HashMap<String, BlockedProgram> = HashMap::new();
    let all = read_rules(&rules)?;
    let covered = coverage_of(&all);
    for r in all.iter().filter(|r| r.ours) {
        let key = path_key(&r.app);
        let e = map.entry(key).or_insert_with(|| BlockedProgram {
            name: Path::new(&r.app)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| r.app.clone()),
            exists: Path::new(&r.app).is_file(),
            path: r.app.clone(),
            inbound: false,
            outbound: false,
            enabled: false,
            active_rules: true,
        });
        if r.inbound {
            e.inbound = true;
        } else {
            e.outbound = true;
        }
        e.enabled |= r.enabled;
    }
    let live: Vec<String> = map.values().map(|b| b.path.clone()).collect();
    store_add(&live);
    for p in store_load() {
        let key = path_key(&p);
        map.entry(key).or_insert_with(|| BlockedProgram {
            name: Path::new(&p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone()),
            exists: Path::new(&p).is_file(),
            path: p,
            inbound: false,
            outbound: false,
            enabled: false,
            active_rules: false,
        });
    }
    // rules made elsewhere count too: they are the reason no second rule is created
    for (key, b) in &mut map {
        for inbound in [true, false] {
            if let Some(&enabled) = covered.get(&(key.clone(), inbound)) {
                if inbound {
                    b.inbound = true;
                } else {
                    b.outbound = true;
                }
                b.enabled |= enabled;
            }
        }
        b.active_rules |= b.inbound && b.outbound;
    }
    let mut v: Vec<_> = map.into_values().collect();
    v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.path.cmp(&b.path)));
    Ok(v)
}

/// Read-only scan of the firewall for existing block rules, from this app or any other.
pub fn coverage() -> Result<Coverage> {
    let _com = ComGuard::new();
    let pol = policy()?;
    let rules = unsafe { pol.Rules() }.map_err(err)?;
    Ok(coverage_of(&read_rules(&rules)?))
}

fn add_rule(rules: &INetFwRules, path: &str, inbound: bool) -> Result<()> {
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(err)?;
    unsafe {
        rule.SetName(&BSTR::from(rule_name(path, inbound))).map_err(err)?;
        rule.SetDescription(&BSTR::from("Blocked by Firewall Manager")).map_err(err)?;
        rule.SetApplicationName(&BSTR::from(path)).map_err(err)?;
        rule.SetDirection(if inbound { NET_FW_RULE_DIR_IN } else { NET_FW_RULE_DIR_OUT })
            .map_err(err)?;
        rule.SetAction(NET_FW_ACTION_BLOCK).map_err(err)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(err)?;
        rule.SetEnabled(VARIANT_TRUE).map_err(err)?;
        rules.Add(&rule).map_err(err)
    }
}

/// Blocks each program in both directions. Only missing directions are created, so a program that
/// already has a block rule never gets a second one.
/// `progress(done, total)` is called after every file.
pub fn block_files(files: &[PathBuf], mut progress: impl FnMut(usize, usize)) -> Result<BlockReport> {
    let _com = ComGuard::new();
    let pol = policy()?;
    let rules = unsafe { pol.Rules() }.map_err(err)?;
    let mut have = coverage_of(&read_rules(&rules)?);
    let mut rep = BlockReport::default();
    for (i, f) in files.iter().enumerate() {
        let p = f.to_string_lossy().into_owned();
        let key = path_key(&p);
        let missing: Vec<bool> = [true, false].into_iter().filter(|&d| !have.contains_key(&(key.clone(), d))).collect();
        if missing.is_empty() {
            rep.skipped += 1;
        } else {
            match missing.iter().try_for_each(|&inbound| add_rule(&rules, &p, inbound)) {
                Ok(()) => {
                    store_add(&[p.clone()]);
                    have.extend(missing.iter().map(|&d| ((key.clone(), d), true)));
                    rep.blocked += 1;
                }
                Err(e) => rep.errors.push(format!("{p}: {e}")),
            }
        }
        progress(i + 1, files.len());
    }
    Ok(rep)
}

fn remove_where(pred: impl Fn(&RawRule) -> bool) -> Result<RemoveReport> {
    let _com = ComGuard::new();
    let pol = policy()?;
    let rules = unsafe { pol.Rules() }.map_err(err)?;
    let mut rep = RemoveReport::default();
    // Rules.Remove deletes by name; one call per matching rule instance.
    // Only this app's rules are ever removed.
    for r in read_rules(&rules)?.into_iter().filter(|r| r.ours && pred(r)) {
        match unsafe { rules.Remove(&BSTR::from(r.name.as_str())) } {
            Ok(()) => rep.removed += 1,
            Err(e) => rep.errors.push(format!("{}: {e}", r.name)),
        }
    }
    Ok(rep)
}

/// Removes every rule of this tool that belongs to one of the given program paths.
pub fn remove_paths(paths: &[String]) -> Result<RemoveReport> {
    let set: HashSet<String> = paths.iter().map(|p| path_key(p)).collect();
    store_remove(Some(&set));
    remove_where(|r| set.contains(&path_key(&r.app)))
}

pub fn remove_all() -> Result<RemoveReport> {
    store_remove(None);
    remove_where(|_| true)
}

/// Recursively collects `.exe` files; unreadable directories are reported, symlinks are not followed.
pub fn scan_exes(root: &Path) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                errors.push(format!("{}: {e}", dir.display()));
                continue;
            }
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file()
                && p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
            {
                files.push(p);
            }
        }
    }
    files.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    (files, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_are_unique_per_path() {
        let a = rule_name(r"C:\A\game.exe", true);
        let b = rule_name(r"C:\B\game.exe", true);
        assert_ne!(a, b);
        assert!(a.starts_with("PSFirewallBlock_game_"));
        assert!(a.ends_with("_Inbound"));
        assert!(rule_name(r"C:\A\game.exe", false).ends_with("_Outbound"));
    }

    #[test]
    fn rule_name_is_case_insensitive_and_sanitised() {
        assert_eq!(rule_name(r"C:\X\My App.exe", true), rule_name(r"c:\x\My App.EXE", true));
        assert!(rule_name(r"C:\X\My App!.exe", true).starts_with("PSFirewallBlock_My_App__"));
    }

    #[test]
    fn store_dir_is_program_files() {
        // The folder exists after the first elevated run; skip when it was never created.
        if let Some(d) = secure_dir() {
            assert!(d.ends_with("FirewallManager"));
            assert!(d.to_string_lossy().to_lowercase().contains("program files"), "{d:?}");
        }
    }

    #[test]
    fn path_key_normalises() {
        assert_eq!(path_key("C:/Foo/Bar.EXE "), r"c:\foo\bar.exe");
    }

    #[test]
    fn path_key_expands_environment_variables() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(path_key(r"%SystemRoot%\a.exe"), path_key(&format!(r"{root}\a.exe")));
        assert_eq!(path_key(r"C:\100%\%nope_fwm%\a.exe"), r"c:\100%\%nope_fwm%\a.exe");
    }

    #[test]
    fn blocked_needs_both_directions() {
        let mut c = Coverage::new();
        c.insert((path_key(r"C:\a.exe"), true), true);
        assert!(!is_blocked(&c, r"C:\A.exe"));
        c.insert((path_key(r"C:\a.exe"), false), false);
        assert!(is_blocked(&c, r"C:\A.exe"));
    }

    #[test]
    fn program_dir_groups_by_install_folder() {
        for (exe, dir) in [
            (r"C:\Program Files\Adobe\Reader\bin\a.exe", r"C:\Program Files\Adobe"),
            (r"C:\Program Files\Common Files\Adobe\x\a.exe", r"C:\Program Files\Common Files\Adobe"),
            (r"C:\Program Files (x86)\Steam\steamapps\common\Doom\x64\a.exe", r"C:\Program Files (x86)\Steam\steamapps\common\Doom"),
            (r"C:\Users\u\AppData\Local\Programs\Tool\a.exe", r"C:\Users\u\AppData\Local\Programs\Tool"),
            (r"C:\Users\u\AppData\Roaming\App\sub\a.exe", r"C:\Users\u\AppData\Roaming\App"),
            (r"D:\Stuff\Thing\bin\x64\a.exe", r"D:\Stuff\Thing"),
            (r"C:\Program Files\a.exe", r"C:\Program Files"),
            (r"D:\a.exe", "D:"),
        ] {
            assert_eq!(program_dir(exe), dir, "{exe}");
        }
    }

    #[test]
    fn scan_finds_exes_recursively() {
        let d = std::env::temp_dir().join(format!("fwm_scan_{}", std::process::id()));
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(d.join("a.exe"), b"").unwrap();
        std::fs::write(sub.join("B.EXE"), b"").unwrap();
        std::fs::write(sub.join("c.dll"), b"").unwrap();
        let (files, errs) = scan_exes(&d);
        std::fs::remove_dir_all(&d).ok();
        assert!(errs.is_empty());
        assert_eq!(files.len(), 2);
    }
}

#[cfg(test)]
mod com_tests {
    use super::*;

    /// Needs an elevated shell: `cargo test -- --ignored`
    #[test]
    #[ignore]
    fn block_list_remove_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fwm_rt_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("fwm_roundtrip.exe");
        std::fs::write(&exe, b"").unwrap();
        let rep = block_files(&[exe.clone()], |_, _| {}).unwrap();
        assert_eq!((rep.blocked, rep.errors.len()), (1, 0), "{:?}", rep);
        let rep = block_files(&[exe.clone()], |_, _| {}).unwrap();
        assert_eq!((rep.blocked, rep.skipped), (0, 1)); // no duplicates
        let t = std::time::Instant::now();
        let l = list_blocked().unwrap();
        println!("list took {:?}", t.elapsed());
        let me = l.iter().find(|b| b.name == "fwm_roundtrip.exe").expect("listed");
        assert!(me.inbound && me.outbound && me.enabled && me.exists);
        // rules wiped behind our back are restored from the remembered list
        let name = rule_name(&exe.to_string_lossy(), true);
        {
            let _c = ComGuard::new();
            let rules = unsafe { policy().unwrap().Rules() }.unwrap();
            unsafe { rules.Remove(&BSTR::from(name)) }.unwrap();
        }
        assert!(!list_blocked().unwrap().iter().find(|b| b.name == "fwm_roundtrip.exe").unwrap().inbound);
        assert!(restore_missing().unwrap() >= 1);
        assert!(list_blocked().unwrap().iter().find(|b| b.name == "fwm_roundtrip.exe").unwrap().inbound);
        let r = remove_paths(&[exe.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(r.removed, 2, "{:?}", r);
        assert!(!list_blocked().unwrap().iter().any(|b| b.name == "fwm_roundtrip.exe"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
