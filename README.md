# Template: Rust Project
Template repository for Rust projects

## Creating a new Rust project from this template

This template repo contains tooling and CI wiring, but it does not ship a Rust crate by default. After creating your repository from the template, initialize a crate in the repository root.

### Binary project (CLI / service)

Create a binary crate in the repository root:

````bash
cargo init --bin
````

### Library project (crate published to crates.io)

Create a library crate in the repository root:

````bash
cargo init --lib
````

## Template TODOs

After creating a new repository from this template, make sure to:


- [ ] If not in `secana` org, replace the `secana` owner in the workflows that are gated by owner:
  - [.github/workflows/release-plz.yml](.github/workflows/release-plz.yml)
  - [.github/workflows/dependabot-auto-merge.yml](.github/workflows/dependabot-auto-merge.yml)
  - [.github/workflows/dependabot-auto-approve.yml](.github/workflows/dependabot-auto-approve.yml)

## Github Settings TODOs

After creating a new repository from this template, make sure to:
- [ ] Enable "Require status checks to pass before merging" in Branch Protection Rules for `main` branch
- [ ] Enable "Allow auto-merge" under "General" settings
- [ ] Add the Actions secret `RELEASE_PLZ_TOKEN` (GitHub token with rights to create releases)
- [ ] Add the Actions secret `CARGO_REGISTRY_TOKEN` to release to crates.io (if applicable)
