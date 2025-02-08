# age-concurrent

A concurrent, API-compatible implementation of [FiloSottile/age](https://github.com/FiloSottile/age), providing efficient encryption and decryption using multiple workers.

## Overview

`age-concurrent` is a drop-in replacement for `age` that accelerates encryption and decryption by utilizing multiple concurrent workers. It maintains full API compatibility with `filippo.io/age`, ensuring seamless integration while enhancing performance.

## Features

- **Concurrent Encryption & Decryption:** Uses `runtime.NumCPU()` workers by default, configurable via `EncryptN` and `DecryptN`.
- **API-Compatible:** Functions and signatures match `filippo.io/age`.

## Installation

```sh
go get github.com/bifrosta/age-concurrent
```

## Usage

### Encrypt

```go
package main

import (
	"os"
	"github.com/bifrosta/age-concurrent"
)

func main() {
	file, _ := os.Create("encrypted.age")
	recipient, _ := age.ParseX25519Recipient("age1...")
	writer, _ := age.Encrypt(file, recipient)
	writer.Write([]byte("Hello, encrypted world!"))
	writer.Close()
}
```

### Decrypt

```go
package main

import (
	"os"
	"github.com/bifrosta/age-concurrent"
)

func main() {
	file, _ := os.Open("encrypted.age")
	identity, _ := age.ParseX25519Identity("AGE-SECRET-KEY-1...")
	reader, _ := age.Decrypt(file, identity)
	io.Copy(os.Stdout, reader)
}
```

### Controlling Concurrency

```go
writer, _ := age.EncryptN(file, 4, recipient) // Use 4 workers
reader, _ := age.DecryptN(file, 4, identity)  // Use 4 workers
```

## Performance

Benchmark results on an AMD Ryzen 9 7950X 16-Core Processor show some
speed improvements with increased concurrency:

| CPU Cores      | Read Speed (MB/s) | Write Speed (MB/s) |
|----------------|-------------------|--------------------|
| (upstream age) | 3179              | 4202               |
| 1              | 3897              | **2682**           |
| 2              | 4760              | 4659               |
| 4              | 5743              | 5484               |
| 8              | 7572              | 7479               |
| 16             | 8758              | 9268               |
| 32             | **7781**          | 10503              |

Higher concurrency levels generally improve performance,
particularly for encryption operations. However, performance
may plateau at very high core counts due to memory bandwidth
and synchronization overhead. Do your own testing to find the
optimal concurrency level for your workload and hardware.

## Experimental Status

Warning: This project is highly experimental and untested.
While it aims to provide improved performance over age, it
has not undergone rigorous security auditing or extensive
testing. Use at your own risk, and do not rely on it for
critical applications without performing your own verification.

## License

`age-concurrent` is licensed under the same terms as `age`. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

Built on top of `filippo.io/age` with performance enhancements for concurrency.

