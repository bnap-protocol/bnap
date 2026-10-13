# BNAP

BNAP is an open protocol for paying for and authorizing machine-to-machine
requests over HTTP and MCP. It describes how a server states what a request
costs and which proofs it accepts, how a client attaches payment or an
authorization proof to the request (for example ecash notes, L402 or MPP), and
how the server verifies that proof before it serves the request. This
repository holds the specification text, reference material and the test
vectors that implementations are checked against.

**Status:** pre-alpha, draft-00. Anything here can change without notice.

## Related repositories

- Specification (this repository): https://github.com/bnap-protocol/bnap
- Caparra, the Rust reference implementation: https://github.com/bnap-protocol/caparra

## License

The specification text is licensed under CC-BY-4.0 (see [LICENSE-SPEC](LICENSE-SPEC)).
Code is licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
