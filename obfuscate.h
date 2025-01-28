#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonHMAC.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>

#pragma mark - Configuration

// Cryptographic parameters
#define kAESKeySize kCCKeySizeAES256        // 256-bit AES key
#define kAESBlockSize kCCBlockSizeAES128    // 128-bit block size
#define kIVSize kCCBlockSizeAES128          // 128-bit initialization vector
#define kHMACSize CC_SHA256_DIGEST_LENGTH   // 256-bit HMAC
#define kSaltSize 32                        // 256-bit salt

// Forward declarations
id obfuscateValue(id value);
id deobfuscateValue(id value);

// String/Number obfuscation macros
#define OBFUSCATE_STR(str) obfuscateValue([NSString stringWithUTF8String:#str])
#define OBFUSCATE_NUM(num) obfuscateValue(@(num))

#pragma mark - Key Generation

/**
 * Generates a runtime-specific encryption key based on system parameters.
 * The key is derived from process information, system time, and executable path
 * to ensure uniqueness across different executions and environments.
 *
 * @return NSData* containing the generated key, or nil if generation fails
 */
NSData* generateRuntimeKey(void) {
  NSMutableData *seedData = [NSMutableData new];
  
  // Collect process-specific identifiers
  pid_t pid = getpid();
  pid_t ppid = getppid();
  [seedData appendBytes:&pid length:sizeof(pid)];
  [seedData appendBytes:&ppid length:sizeof(ppid)];
  
  // Include system boot time for temporal uniqueness
  struct timeval bootTime;
  size_t size = sizeof(bootTime);
  if (sysctl((int[]){CTL_KERN, KERN_BOOTTIME}, 2, &bootTime, &size, NULL, 0)
      == 0) {
    [seedData appendBytes:&bootTime length:sizeof(bootTime)];
  }
  
  // Add executable path for spatial uniqueness
  const char* exePath = [[[NSBundle mainBundle] executablePath] UTF8String];
  [seedData appendBytes:exePath length:strlen(exePath)];
  
  // Generate final key using SHA-256
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(seedData.bytes, (CC_LONG)seedData.length, hash);
  
  return [NSData dataWithBytes:hash length:sizeof(hash)];
}

#pragma mark - Cryptographic Utilities

/**
 * Generates a cryptographically secure random initialization vector.
 * Falls back to arc4random if secure random generation fails.
 *
 * @return NSData* containing the random IV
 */
static NSData* generateRandomIV(void) {
  NSMutableData *iv = [NSMutableData dataWithLength:kIVSize];
  int result = SecRandomCopyBytes(kSecRandomDefault, kIVSize, iv.mutableBytes);
  if (result != errSecSuccess) {
    arc4random_buf(iv.mutableBytes, kIVSize);
  }
  return iv;
}

/**
 * Calculates HMAC-SHA256 for the provided data using the given key.
 *
 * @param data The data to authenticate
 * @param key The key to use for HMAC calculation
 * @return NSData* containing the calculated HMAC
 */
static NSData* calculateHMAC(NSData *data, NSData *key) {
  NSMutableData *hmac = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length,
         hmac.mutableBytes);
  return hmac;
}

#pragma mark - Encryption/Decryption

/**
 * Encrypts data using AES-256 in CBC mode with HMAC verification.
 * Format: [IV (16 bytes)][Encrypted Data][HMAC (32 bytes)]
 *
 * @param data The data to encrypt
 * @param key The encryption key
 * @return NSData* containing the encrypted data with IV and HMAC
 */
static NSData* encryptData(NSData* data, NSData* key) {
  if (!data || !key) return nil;
  
  NSData *iv = generateRandomIV();
  size_t bufferSize = data.length + kCCBlockSizeAES128;
  NSMutableData *buffer = [NSMutableData dataWithLength:bufferSize];
  size_t numBytesEncrypted = 0;
  
  CCCryptorStatus cryptStatus = CCCrypt(
    kCCEncrypt,
    kCCAlgorithmAES,
    kCCOptionPKCS7Padding,
    key.bytes,
    key.length,
    iv.bytes,
    data.bytes,
    data.length,
    buffer.mutableBytes,
    bufferSize,
    &numBytesEncrypted
  );
  
  if (cryptStatus != kCCSuccess) {
    return nil;
  }
  
  [buffer setLength:numBytesEncrypted];
  
  NSMutableData *result = [NSMutableData dataWithData:iv];
  [result appendData:buffer];
  
  NSData *hmac = calculateHMAC(result, key);
  [result appendData:hmac];
  
  return result;
}

/**
 * Decrypts data that was encrypted using encryptData.
 * Verifies HMAC before attempting decryption.
 *
 * @param data The data to decrypt (including IV and HMAC)
 * @param key The decryption key
 * @return NSData* containing the decrypted data, or nil if verification fails
 */
static NSData* decryptData(NSData* data, NSData* key) {
  if (!data || !key || data.length <= (kIVSize + kHMACSize)) {
    return nil;
  }
  
  // Verify HMAC
  NSData *receivedHmac = [data subdataWithRange:
    NSMakeRange(data.length - kHMACSize, kHMACSize)];
  NSData *encryptedData = [data subdataWithRange:
    NSMakeRange(0, data.length - kHMACSize)];
  NSData *calculatedHmac = calculateHMAC(encryptedData, key);
  
  if (![receivedHmac isEqualToData:calculatedHmac]) {
    return nil;
  }
  
  // Extract IV and ciphertext
  NSData *iv = [encryptedData subdataWithRange:NSMakeRange(0, kIVSize)];
  NSData *actualEncryptedData = [encryptedData subdataWithRange:
    NSMakeRange(kIVSize, encryptedData.length - kIVSize)];
  
  size_t bufferSize = actualEncryptedData.length + kCCBlockSizeAES128;
  NSMutableData *buffer = [NSMutableData dataWithLength:bufferSize];
  size_t numBytesDecrypted = 0;
  
  CCCryptorStatus cryptStatus = CCCrypt(
    kCCDecrypt,
    kCCAlgorithmAES,
    kCCOptionPKCS7Padding,
    key.bytes,
    key.length,
    iv.bytes,
    actualEncryptedData.bytes,
    actualEncryptedData.length,
    buffer.mutableBytes,
    bufferSize,
    &numBytesDecrypted
  );
  
  if (cryptStatus != kCCSuccess) {
    return nil;
  }
  
  [buffer setLength:numBytesDecrypted];
  return buffer;
}

#pragma mark - Public Interface

/**
 * Obfuscates a value using AES-256 encryption.
 * Supports NSString and NSNumber types.
 *
 * @param value The value to obfuscate
 * @return id The obfuscated value as a base64 encoded string
 */
id obfuscateValue(id value) {
  static NSData *runtimeKey = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    runtimeKey = generateRuntimeKey();
  });
  
  if ([value isKindOfClass:[NSString class]]) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = encryptData(data, runtimeKey);
    return [encryptedData base64EncodedStringWithOptions:0];
    
  } else if ([value isKindOfClass:[NSNumber class]]) {
    NSString *stringValue = [value stringValue];
    NSData *data = [stringValue dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = encryptData(data, runtimeKey);
    return [encryptedData base64EncodedStringWithOptions:0];
  }
  
  return value;
}

/**
 * Deobfuscates a previously obfuscated value.
 * Automatically detects and converts numeric values.
 *
 * @param value The value to deobfuscate
 * @return id The original value, either as NSString or NSNumber
 */
id deobfuscateValue(id value) {
  static NSData *runtimeKey = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    runtimeKey = generateRuntimeKey();
  });
  
  if ([value isKindOfClass:[NSString class]]) {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:value options:0];
    if (!data) return value;
    
    NSData *decryptedData = decryptData(data, runtimeKey);
    if (!decryptedData) return value;
    
    NSString *decryptedString = [[NSString alloc]
      initWithData:decryptedData
      encoding:NSUTF8StringEncoding];
    
    NSNumberFormatter *formatter = [[NSNumberFormatter alloc] init];
    formatter.numberStyle = NSNumberFormatterDecimalStyle;
    NSNumber *number = [formatter numberFromString:decryptedString];
    return number ?: decryptedString;
  }
  
  return value;
}