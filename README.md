# coretrust_cli

A simple CLI tool that directly calls CoreTrust functions for code signature validation. It uses frameworks inside the dyld shared cache that export the CoreTrust functions (MobileInBoxUpdate.framework on iOS, AuthKit.framework on macOS) in order to call them from userland. Said functions are identical to the ones used in the main CoreTrust kernel extension.

This is useful if you're testing CoreTrust functionality or evaluation. You can call any of the symbols exported by the frameworks directly from the CLI, as long as you define them in `CoreTrust.h` (you can find a lot of function signatures [here](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/CoreTrust/CTEvaluate.h)). By default, the tool will call `CTEvaluateAmfiCodeSignatureCMS` and is configured to extract the necessary components from the binary to pass to the function.

This tool also enables you to use LLDB to debug and step through the CoreTrust flow. This allows you to modify memory, inspect structures, set breakpoints and understand the CoreTrust flow better.

`coretrust_cli` will return the result of the CoreTrust evaluation and, if successful, the policy flags returned by CoreTrust, and the CD hash that AMFI would check against after CoreTrust evaluation.

Running `make` will build for both macOS and iOS. macOS binaries will be placed in `output/coretrust_cli` and iOS binaries will be placed in `output/ios/coretrust_cli`.

This project depends on [ChOma](https://github.com/opa334/ChOma) for the Mach-O and code signature parsing. The necessary files are in the `include` and `lib` directories, in compiled form. ChOma, like `coretrust_cli`, is licensed under the MIT license.

```sh
➜  coretrust_cli git:(main) ✗ output/coretrust_cli -i /sbin/reboot
CoreTrust evaluation was successful!
CoreTrust policy flags (0x8):
 - Mac Platform

CMS uses Apple Hash Agility V2, chosen hash type is SHA-256.
AMFI will expect CD hash of SHA-256 code directory to be 6deaa31d0c5b0209bb11254cc6d445bc94b50bd0ed09db26375e678d600528e5.
```

## Usage

```sh
Options: 
        -i: input file
        -h: print this help message
Examples:
        ./coretrust_cli -i <path to input binary>
```