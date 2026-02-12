declare module 'age-encryption/dist/io.js' {
  export interface ReadableStreamWithSize extends ReadableStream<Uint8Array> {
    size(sourceSize: number): number;
  }

  export function stream(a: Uint8Array): ReadableStream<Uint8Array>;
  export function readAll(stream: ReadableStream<Uint8Array> | ReadableStreamWithSize): Promise<Uint8Array>;
  export async function readAllString(stream: ReadableStream): Promise<string>;
  export async function read(stream: ReadableStream<Uint8Array>, n: number): Promise<{
    data: Uint8Array;
    rest: ReadableStream<Uint8Array>;
  }>;
  export function flatten(arr: Uint8Array[]): Uint8Array;
  export function prepend(s: ReadableStream<Uint8Array> | ReadableStreamWithSize, ...prefixes: Uint8Array[]): ReadableStreamWithSize;
  export function randomBytesStream(n: number, chunk: number): ReadableStream<Uint8Array>;
}

declare module 'age-encryption/armor.js' {
  export function encode(file: Uint8Array): string;
  export function decode(file: string): Uint8Array;
}

declare module 'age-encryption/recipients.js' {
  export function generateIdentity(): Promise<string>;
  export function generateHybridIdentity(): Promise<string>;
  export function generateX25519Identity(): Promise<string>;
  export function identityToRecipient(identity: string | CryptoKey): Promise<string>;
}
