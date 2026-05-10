// Emit GIT_DESCRIBE — "v0.1.0-3-gabc1234" plus "-modified" when the working
// tree is dirty — for `src/main.rs` to concatenate into the `--version`
// string via env!().  Falls back to "unknown" when there's no .git
// (source-tarball builds), so the binary still builds.
//
// Implemented directly via `git` rather than a vergen-style crate to avoid
// pulling in a build-deps subtree that would track ahead of our MSRV.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves or a tag is created/removed.  This is a
    // best-effort heuristic — it misses dirty-tree transitions, but the
    // dirty marker is cosmetic for --version output, not load-bearing.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    let describe = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty=-modified"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_DESCRIBE={describe}");
}
