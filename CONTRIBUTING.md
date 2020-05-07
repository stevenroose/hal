


# Packaging


## Creating the RPM file

We use a modification of the cargo-rpm tool to generate the RPM file.

```
$ git clone https://github.com/stevenroose/cargo-rpm.git
$ cd cargo-rpm
$ cargo build --release --target-dir ./target
$ cd ..
$ ./cargo-rpm/target/release/cargo-rpm rpm build
$ rm -rf ./cargo-rpm
```

The RPM is created inside the target dir:
```
<target-dir>/release/rpmbuild/RPMS/x86_64/hal-bitcoin-x.y.z-1.x86_64.rpm
```
