# blockdiff

Fast block-level file diffs (e.g. for VM disk images) using CoW filesystem metadata

## Usage

Creating a snapshot:

```
blockdiff create target.img base.img output.bdiff
```

Applying a snapshot:

```
blockdiff apply target.img base.img input.bdiff
```
