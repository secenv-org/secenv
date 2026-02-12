import { 
  SecenvError, 
  IdentityNotFoundError, 
  DecryptionError, 
  SecretNotFoundError, 
  ParseError, 
  FileError, 
  EncryptionError,
  SECENV_ERROR_CODES
} from '../../src/errors.js';

describe('Error Classes (errors.ts)', () => {
  it('should have correct error codes', () => {
    expect(SECENV_ERROR_CODES.IDENTITY_NOT_FOUND).toBe('IDENTITY_NOT_FOUND');
    expect(SECENV_ERROR_CODES.DECRYPTION_FAILED).toBe('DECRYPTION_FAILED');
    expect(SECENV_ERROR_CODES.SECRET_NOT_FOUND).toBe('SECRET_NOT_FOUND');
    expect(SECENV_ERROR_CODES.PARSE_ERROR).toBe('PARSE_ERROR');
    expect(SECENV_ERROR_CODES.FILE_ERROR).toBe('FILE_ERROR');
    expect(SECENV_ERROR_CODES.ENCRYPTION_FAILED).toBe('ENCRYPTION_FAILED');
  });

  it('IdentityNotFoundError should have correct code and message', () => {
    const error = new IdentityNotFoundError('/path/to/key');
    expect(error.code).toBe(SECENV_ERROR_CODES.IDENTITY_NOT_FOUND);
    expect(error.message).toContain('/path/to/key');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('DecryptionError should have correct code and message', () => {
    const error = new DecryptionError('custom message');
    expect(error.code).toBe(SECENV_ERROR_CODES.DECRYPTION_FAILED);
    expect(error.message).toBe('custom message');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('SecretNotFoundError should have correct code and message', () => {
    const error = new SecretNotFoundError('MY_KEY');
    expect(error.code).toBe(SECENV_ERROR_CODES.SECRET_NOT_FOUND);
    expect(error.message).toContain('MY_KEY');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('ParseError should have correct code, message, and properties', () => {
    const error = new ParseError(10, 'KEY VAL', 'Missing equals');
    expect(error.code).toBe(SECENV_ERROR_CODES.PARSE_ERROR);
    expect(error.message).toBe('Missing equals');
    expect(error.line).toBe(10);
    expect(error.raw).toBe('KEY VAL');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('FileError should have correct code and message', () => {
    const error = new FileError('disk full');
    expect(error.code).toBe(SECENV_ERROR_CODES.FILE_ERROR);
    expect(error.message).toBe('disk full');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('EncryptionError should have correct code and message', () => {
    const error = new EncryptionError('invalid input');
    expect(error.code).toBe(SECENV_ERROR_CODES.ENCRYPTION_FAILED);
    expect(error.message).toBe('invalid input');
    expect(error).toBeInstanceOf(SecenvError);
  });

  it('SecenvError should be an instance of Error', () => {
    const error = new SecenvError(SECENV_ERROR_CODES.FILE_ERROR, 'msg');
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('SecenvError');
  });
});
