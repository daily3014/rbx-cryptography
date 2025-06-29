# Contributing

We welcome contributions to improve the library.
All contributors must follow the steps and guidelines defined below.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/daily3014/rbx-cryptography.git`
3. Install dependencies if needed
4. Start development server: `bash scripts/dev.sh`

## Guidelines

- **Bug Reports**: Use issues with reproduction steps
- **Feature Requests**: Open an issue to discuss before implementing
- **Pull Requests**: 
  - Follow existing code style
  - Add tests for new features
  - Make sure all tests pass

## Adding New Algorithms

When contributing new cryptographic algorithms:
1. Implement the algorithm in the appropriate module (Hashing, Encryption, etc.)
2. Add tests
4. Add performance benchmarks
5. Submit a pull request