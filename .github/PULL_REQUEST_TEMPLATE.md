## What

<!-- Brief description of changes -->

## Why

<!-- Motivation / issue reference -->

## Checklist

- [ ] Tests pass (`cargo test`)
- [ ] No new clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Updated CHANGELOG.md (if user-facing change)
- [ ] New registry? See CONTRIBUTING.md checklist
- [ ] **Commits are signed** — `main` requires verified signatures, so an unsigned commit cannot be merged even with green CI and an approval

<!--
Signing, if it is not set up yet. SSH is the short road: add your existing public
key to GitHub a second time, choosing key type "Signing key", then

    git config gpg.format ssh
    git config user.signingkey ~/.ssh/id_ed25519.pub
    git commit --amend -S --no-edit
    git push --force-with-lease

With GPG instead: git config user.signingkey <key-id>, then the same amend.
The commit email must match a verified address on your account, or GitHub still
shows "Unverified". Details: CONTRIBUTING.md, section "Sign your commits".
-->
