# Preparing an Apache server for Alice

This guide is completed in a later task. It already quotes the sudoers lines of the `apache` profile.

## The Apache profile

The `apache` profile adds these lines to `/etc/sudoers.d/alice` (exactly as the setup commands write them):

```
Cmnd_Alias ALICE_APACHE_ONLY = \
    /usr/local/libexec/alice-helper apache-dump

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_APACHE_ONLY
```
