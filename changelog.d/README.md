# Changelog fragments

Each unreleased change gets its own file in this directory. Pull requests do not edit
[`CHANGELOG.md`](../CHANGELOG.md): when every PR adds its entry under the same
`## [Unreleased]` heading, any two open PRs conflict. Separate files never do. CI fails a
PR that edits `CHANGELOG.md`, unless the PR is a release (see below).

## Adding an entry

Create `changelog.d/<YYYYMMDD>_<ticket-id>.md`, for example
`changelog.d/20260929_lab-6153.md`, using the date you write it. The file holds the entry
exactly as it will appear in the changelog: a `###` heading naming the area and the change,
then bullets.

```markdown
### Wire format — short statement of the change (LAB-1234)

- What changed, with a link to the spec section.
- **Breaking for …:** who is affected and how to migrate, when it applies.
```

Files are collected in filename order, so the date prefix keeps entries in merge order.
A change that needs no changelog entry does not add a file.

## Releasing

Releases are cut from a branch named `release/<version>`. That prefix is the CI exemption.

```bash
git checkout -b release/1.1.0 origin/main
uvx scriv@1.8.0 collect --version 1.1.0
```

`scriv collect` writes a `## [1.1.0] - <date>` section at the
`<!-- scriv-insert-here -->` marker in `CHANGELOG.md` and deletes the collected fragments.
This README and `scriv.ini` stay, and so do both markers. Entries written before this
directory existed sit below `<!-- scriv-end-here -->`, so the first release's section
picks them up without a hand edit.
