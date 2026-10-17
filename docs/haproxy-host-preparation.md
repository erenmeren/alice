# Preparing a HAProxy server for Alice

Alice reads the certificates of a HAProxy server. **On a HAProxy server Alice only reads.** This guide is a skeleton
that is completed with the HAProxy provider.

## The HAProxy profile

The `haproxy` profile adds these lines to `/etc/sudoers.d/alice` (exactly as the setup commands write them):

```
Cmnd_Alias ALICE_HAPROXY_ONLY = \
    /usr/local/libexec/alice-helper haproxy-dump

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_HAPROXY_ONLY
```

`ALICE_COMMON` is the SSH-key part that every profile has. `haproxy-dump` takes no arguments: sudo refuses any
further word, and the helper refuses any argument itself.
