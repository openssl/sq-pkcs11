// Emit VERGEN_GIT_DESCRIBE — "v0.1.0-3-gabc1234" plus "-modified" when the
// working tree is dirty — for `--version` to embed at compile time.
//
// `.idempotent()` makes vergen emit a placeholder rather than failing when
// .git is absent (e.g. building from a source tarball), so the binary still
// builds.  In that case `--version` will show "VERGEN_IDEMPOTENT_OUTPUT".

use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git = GitclBuilder::default()
        .describe(
            /* tags */ true, /* dirty */ true, /* match */ None,
        )
        .build()?;

    Emitter::default()
        .idempotent()
        .add_instructions(&git)?
        .emit()?;

    Ok(())
}
