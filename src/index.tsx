import { NativeModules, Platform } from 'react-native';
import { generateKeyPair as genKeyPair, sharedKey, sign as curveSign, verify as curveVerify} from 'curve25519-js'
import arrayBufferToHex from 'array-buffer-to-hex';
import { TextEncoder } from "web-encoding"

const hexToArray = (input:string):Uint8Array => {
  const view = new Uint8Array(input.length / 2);

  for (let i = 0; i < input.length; i += 2) {
    view[i / 2] = parseInt(input.substring(i, i + 2), 16);
  }

  return view;
}

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

const random = ():string => {
   
   let a = '';
    for(a = ''; a.length < 32;) a += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz"[(Math.random() * 60) | 0];
    return a;
  }
export const encode = (text:string):Uint8Array =>
  new TextEncoder().encode(text)

export function generateKeypair(): Promise<string> {
  if (Platform.OS === "android") return Ed25519Rn.generateKeypair();

  const pair = genKeyPair(encode(random()));
  return Promise.resolve(arrayBufferToHex(pair.private.buffer) + arrayBufferToHex(pair.public.buffer));
}

export function getPublicKey(keyPair: string): Promise<string> {
  if (Platform.OS === "android") return Ed25519Rn.getPublicKey(keyPair);

  return Promise.resolve(keyPair.slice(64));
}

export function getSharedKey(
  keyPair: string,
  otherPublicKey: string
): Promise<string> {

  if (Platform.OS === "android") return Ed25519Rn.getSharedKey(keyPair, otherPublicKey);

  const mine =   hexToArray(keyPair.slice(0, 64));
  const theirs = hexToArray(otherPublicKey);
  const secret = sharedKey(mine, theirs);

  return Promise.resolve(arrayBufferToHex(secret.buffer));
}

export function sign(keyPair: string, data: string): Promise<string> {
  if (Platform.OS === "android") return Ed25519Rn.sign(keyPair, data);

  const mine = hexToArray(keyPair.slice(0, 64));

  return Promise.resolve(
      arrayBufferToHex(
        curveSign(mine, encode(data), encode(Date.now()+''))
        .buffer));
}

export function verify(publicKey: string, data: string, signature: string): Promise<boolean> {
  if (Platform.OS === "android") return  Ed25519Rn.verify(publicKey, data, signature);

  return Promise.resolve(
      curveVerify(
        hexToArray(publicKey),
        hexToArray(data),
        hexToArray(signature),    
    )
  );
}
