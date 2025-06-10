# rbx cryptography by daily3014 and xoifail

> [!WARNING]
> This is the beta branch, some algorithms haven't been fully tested and may produce incorrect results

Devforum Documentation: https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271 \
Wally link: https://wally.run/package/daily3014/cryptography \
Pesde link: https://pesde.dev/packages/daily3014/cryptography

## Why use this one?

Through extensive optimizations, our implementations are 2x-4x faster than alternatives while also trying to stay somewhat readable.

## Will you add other algorithms?

Maybe!

## Contributing

To easily run tests often while developing, run the following command in the terminal:

```bash
bash scripts/dev.sh
```

This will start a Rojo server. Open Roblox Studio and sync Rojo into a Baseplate. Whenever you run the game server, the test suites will run and results will show in the Output widget.

## Testing

To run the test suite, run the following command in the terminal:

```bash
bash scripts/test.sh
```

This will launch and run the test suite in Roblox Studio, and forward the results to the terminal.
