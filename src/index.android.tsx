import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'ed25519-rn' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

const Ed25519Rn = NativeModules.Ed25519Rn
  ? NativeModules.Ed25519Rn
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export async function androidGenerateKeypair(): Promise<string> {
  return Ed25519Rn.generateKeypair();
}

export async function androidGetPublicKey(keyPair: string): Promise<string> {
  return Ed25519Rn.getPublicKey(keyPair);
}

export async function androidGetSharedKey(
  keyPair: string,
  otherPublicKey: string
): Promise<string> {
  return Ed25519Rn.getSharedKey(keyPair, otherPublicKey);
}

export async function androidSign(keyPair: string, data: string): Promise<string> {
  return Ed25519Rn.sign(keyPair, data);
}

export async function androidVerify(publicKey: string, data: string, signature: string): Promise<boolean> {
  return Ed25519Rn.verify(publicKey, data, signature);
}