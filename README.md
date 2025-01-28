# 🛡️ iOS Data Protection Framework

Introducing a powerful data obfuscation framework designed specifically for iOS development. This framework provides enterprise-grade protection for your sensitive data using AES-256 encryption with CBC mode and HMAC integrity verification.

## 🚀 Features

### Data Obfuscation
- 🔐 AES-256 encryption in CBC mode
- 🔑 Secure random IV generation
- ✅ HMAC-SHA256 integrity verification
- 🔄 Runtime-based key derivation
- 📱 Optimized for iOS tweak development
- 💪 Support for NSString and NSNumber types

## Installation

1. Add the framework to your project:
```bash
# Copy obfuscate.h to your project directory
cp obfuscate.h YourProject/
```

2. Import the header in your tweak:
```objc
#import "obfuscate.h"
```

## Usage

### String Obfuscation

```objc
// Obfuscate a string constant
NSString *hidden = OBFUSCATE_STR(MySecretString);

// Deobfuscate the string
NSString *original = deobfuscateValue(hidden);
```

### Number Obfuscation

```objc
// Obfuscate an integer
NSString *hiddenNum = OBFUSCATE_NUM(42);

// Obfuscate a float
NSString *hiddenFloat = OBFUSCATE_NUM(3.14);

// Deobfuscate numbers
id originalNum = deobfuscateValue(hiddenNum);
id originalFloat = deobfuscateValue(hiddenFloat);
```

### Complete Example

```objc
// String example
NSString *secretName = OBFUSCATE_STR(MyTweak);
NSString *secretPath = OBFUSCATE_STR(/path/to/secret);

// Number example
NSString *offset = OBFUSCATE_NUM(0x1234);
NSString *value = OBFUSCATE_NUM(42.5);

// Deobfuscation
NSString *name = deobfuscateValue(secretName);
NSString *path = deobfuscateValue(secretPath);
id offsetValue = deobfuscateValue(offset);
id numericValue = deobfuscateValue(value);
```

## Security Features

1. **AES-256 Encryption**
   - Industry-standard encryption algorithm
   - CBC mode for enhanced security
   - Random IV for each encryption

2. **HMAC Verification**
   - SHA-256 based integrity checking
   - Prevents tampering with encrypted data
   - Ensures data authenticity

3. **Runtime Protection**
   - Dynamic key generation
   - Process-specific encryption
   - Memory protection measures

## Best Practices

1. **String Protection**
   ```objc
   // DON'T store sensitive strings directly
   NSString *bad = @"sensitive_data";
   
   // DO use obfuscation
   NSString *good = OBFUSCATE_STR(sensitive_data);
   ```

2. **Number Protection**
   ```objc
   // DON'T use raw numbers for sensitive values
   float bad = 1234.56;
   
   // DO obfuscate important numbers
   NSString *good = OBFUSCATE_NUM(1234.56);
   ```

3. **Key Management**
   - The framework handles key generation automatically
   - Keys are derived from runtime parameters
   - Each process gets unique encryption keys

## Technical Details

- **Encryption**: AES-256-CBC with PKCS7 padding
- **IV Size**: 128 bits (randomly generated)
- **HMAC**: SHA-256 (32 bytes)
- **Key Derivation**: Runtime-based using process information
- **Memory Safety**: Secure memory handling and cleanup

## Credits

Created by Batchh
Copyright (c) 2025. All rights reserved.

## Security Notice

While this framework provides strong encryption, it's important to note that no security measure is perfect. Always follow security best practices and keep your implementation up to date.
