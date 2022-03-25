# A simple singleton exerciser

A basic tool for testing a singleton implementation on chia.

This is i believe minimal complete example of a wallet-like driver for a
chialisp program that acts as a singleton matching chia's singleton behavior.

It can be used for own versions or as a starting point for trying out singleton
like code on chia.

By default, it creates a singleton with 1 mojo.

Requires chia-dev-tools

Usage:

    (venv) $ cdv clsp treehash testprog.hex
    ZZZZ...
    (venv) $ test-singleton.py --singleton singleton.hex --create-singleton-with-program testprog.hex
    ...
    new puzzle hash: AAAA...
    completed singleton: BBBB...
    (venv) $ test-singleton.py --singleton singleton.hex --inner-puzzle testprog.hex --inner-solution $(opc '(((51 0xZZZZ... 1)))') --continue-singleton BBBB...
    ...
    new puzzle hash: CCCC...
    continued singleton: DDDD...

If the inner puzzle has an evolving state, one should compute a new puzzle hash
for each spend.
