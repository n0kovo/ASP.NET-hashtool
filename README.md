# ASP.NET-hashtool
Generate ASP.NET MVC4/Web Forms password hashes and convert MVC4 hashes to a hashcat-compatible format.

#### Two modes for generation:
- SimpleMembershipProvider (MVC4)
   - PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
- DefaultMembershipProvider (Web Forms)
   - SHA256 with 128-bit salt 

#### One mode for conversion:
- SimpleMembershipProvider (MVC4)
  - Outputs hashcat mode 12000 hashes

### Install:
```console
go install github.com/n0kovo/ASP.NET-hashtool@latest
```

### Usage:
```console
This application either generates or converts ASP.NET MVC4/Web Forms password hashes.
Convert mode (default) reads hashes from stdin and writes hashcat mode 12000 compatible hashes to stdout.
Generate mode (-g) reads plaintext from stdin and writes hashes to stdout.
Flags:
 -a, --advanced-help        print help message for advanced hashing options
 -d, --delimiter            delimiter to split username and salt+hash if --username is used (default: ",")
 -g, --generate             generate hashes from plaintext input instead of converting
 -h, --help                 print this help message
 -m, --max-workers          maximum number of workers (goroutines) to use. 0 = no limit (default))
 -M, --mode                 Choose between MVC4 (SimpleMembershipProvider) and WebForms (DefaultMembershipProvider) when generating hashes. Defaults to MVC4
 -q, --quiet                suppress output
 -r, --rate-limit           number of lines per second to process. 0 = no limit
 -u, --username             indicates if the input is prefixed with a username
```
```console
Advanced options:
 -i, --iter                 number of PBKDF2 iterations (default: 1000)
 -s, --salt-size            salt size in bytes (default: 16 = 128 bits)
 -l, --subkey-length        PBKDF2 subkey length in bytes (default: 32 = 256 bits)

WARNING: Changing these parameters will result in hashes that are incompatible with ASP.NET MVC4.
```

### References:
[https://stackoverflow.com/questions/12544790/use-the-salt-when-using-simplemembershipprovider/12545172#12545172](https://stackoverflow.com/questions/12544790/use-the-salt-when-using-simplemembershipprovider/12545172#12545172)
[https://hashcat.net/forum/thread-1752.html](https://hashcat.net/forum/thread-1752.html)
