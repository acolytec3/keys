import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { pki, util } from 'node-forge'
import { HMACDRBG } from '@stablelib/hmac-drbg'
export const mnemonic = () => {
    return generateMnemonic(wordlist, 256)
}

const getRng = (seed: Uint8Array) => {
    const drbg = new HMACDRBG(undefined, undefined, seed)
    return {
        getBytesSync: (size: number) => {
            return util.binary.raw.encode(drbg.randomBytes(size))
        }
    }
}

const parseForgePrivateKey = (privateKey: pki.rsa.PrivateKey) => {
    const { n, e, d, p, q, dP, dQ, qInv } = privateKey;

    return {
        modulus: new Uint8Array(n.toByteArray()),
        publicExponent: e.intValue(),
        privateExponent: new Uint8Array(d.toByteArray()),
        prime1: new Uint8Array(p.toByteArray()),
        prime2: new Uint8Array(q.toByteArray()),
        exponent1: new Uint8Array(dP.toByteArray()),
        exponent2: new Uint8Array(dQ.toByteArray()),
        coefficient: new Uint8Array(qInv.toByteArray()),
    };
};

const parseForgePublicKey = (publicKey: pki.rsa.PublicKey) => {
    const { n, e } = publicKey;

    return {
        modulus: new Uint8Array(n.toByteArray()),
        publicExponent: e.intValue(),
    };
};

export const generateKey = (mnemonic: string) => {
    const seed = mnemonicToSeedSync(mnemonic)

    const random = {
        randomBytes: () => seed,
        isAvailable: true
    }

    const keypair = pki.rsa.generateKeyPair(4096, 65537, { //@ts-ignore
        prng: getRng(seed)
    })

    return {
        privateKey: parseForgePrivateKey(keypair.privateKey),
        publicKey: parseForgePublicKey(keypair.publicKey)
    }
}

